// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * The IPsec feature: inbound ESP crypto offload, rfc4106(gcm(aes)) over IPv4
 * without ESN, decrypted by KNOD_BLOB_GDA_ENGINE_IPSEC on the packets it
 * passes.  The stack's esp_input() takes the ESP header and trailer off and
 * checks the replay window, as for any crypto offload.
 *
 * The engine looks an SA up by its SPI in a table the host fills, and copies
 * the AES T-tables into LDS when the shader starts.
 */
#include <linux/io.h>
#include <linux/rwsem.h>
#include <linux/unaligned.h>
#include <crypto/aes.h>
#include <crypto/gf128mul.h>
#include <net/xfrm.h>
#include "kfd_priv.h"
#include "kfd_knod.h"
#include "knod_persistent.h"

#define KNOD_IPSEC_SA_MASK	(KNOD_PERSIST_IPSEC_SA_MAX - 1)
#define KNOD_IPSEC_HPOW		256
#define KNOD_IPSEC_RK_BYTES	(4 * AES_MAX_KEYLENGTH_U32)
#define KNOD_IPSEC_KEYS_BYTES	(KNOD_IPSEC_RK_BYTES + 16 * KNOD_IPSEC_HPOW)

struct knod_ipsec_sa {
	struct xfrm_state *x;	/* from state_add to state_free */
	struct knod_mem *keys;	/* rk and hpow */
};

struct knod_ipsec {
	struct knod *knod;
	struct knod_gda_engine engine;
	struct knod_mem *ttab;
	struct knod_mem *table;
	spinlock_t lock;	/* sa[].x */
	u32 nr_sa;
	struct knod_ipsec_sa sa[KNOD_PERSIST_IPSEC_SA_MAX];
};

#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)
/* state_add against the feature going away. */
static DECLARE_RWSEM(knod_ipsec_rwsem);

static struct knod_persistent_ipsec_sa __iomem *
knod_ipsec_entry(struct knod_ipsec *ip, u32 slot)
{
	return (struct knod_persistent_ipsec_sa __iomem *)ip->table->kaddr +
	       slot;
}

static void knod_ipsec_publish(struct knod_ipsec *ip)
{
	/* Publish CPU BAR writes before the shader consumes them. */
	wmb();
	amdgpu_device_flush_hdp(ip->knod->process->pdds[0]->dev->adev, NULL);
}

static struct knod_mem *knod_ipsec_alloc(struct knod *knod, size_t size)
{
	struct knod_mem *mem;

	mem = knod_alloc_mem(knod, size,
			     KFD_IOC_ALLOC_MEM_FLAGS_VRAM |
			     KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
			     KFD_IOC_ALLOC_MEM_FLAGS_COHERENT);
	if (IS_ERR_OR_NULL(mem))
		return NULL;
	memset_io((void __iomem *)mem->kaddr, 0, size);
	return mem;
}

static struct knod_ipsec *knod_ipsec_of(struct knod_dev *knodev)
{
	struct knod *knod = READ_ONCE(knodev->accel->priv);

	return knod ? knod->ipsec : NULL;
}

/* The SPI as the engine reads it from the packet. */
static u32 knod_ipsec_spi(const struct xfrm_state *x)
{
	return get_unaligned_le32(&x->id.spi);
}

static bool knod_ipsec_chacha(const struct xfrm_state *x)
{
	return !strcmp(x->aead->alg_name, "rfc7539esp(chacha20,poly1305)");
}

static int knod_ipsec_validate(struct xfrm_state *x,
			       struct netlink_ext_ack *extack)
{
	u32 key_bits;

	if (x->xso.type != XFRM_DEV_OFFLOAD_CRYPTO ||
	    (x->xso.dir != XFRM_DEV_OFFLOAD_IN &&
	     x->xso.dir != XFRM_DEV_OFFLOAD_OUT)) {
		NL_SET_ERR_MSG(extack, "knod: crypto offload only");
		return -EOPNOTSUPP;
	}
	if (x->props.family != AF_INET || x->id.proto != IPPROTO_ESP) {
		NL_SET_ERR_MSG(extack, "knod: ESP over IPv4 only");
		return -EOPNOTSUPP;
	}
	if (x->props.mode != XFRM_MODE_TRANSPORT &&
	    x->props.mode != XFRM_MODE_TUNNEL) {
		NL_SET_ERR_MSG(extack, "knod: transport or tunnel mode only");
		return -EOPNOTSUPP;
	}
	if (x->props.flags & XFRM_STATE_ESN) {
		NL_SET_ERR_MSG(extack, "knod: no ESN");
		return -EOPNOTSUPP;
	}
	if (x->encap) {
		NL_SET_ERR_MSG(extack, "knod: no UDP encapsulation");
		return -EOPNOTSUPP;
	}
	if (!x->aead || x->ealg || x->aalg || x->calg ||
	    x->aead->alg_icv_len != 128 ||
	    (strcmp(x->aead->alg_name, "rfc4106(gcm(aes))") &&
	     !knod_ipsec_chacha(x))) {
		NL_SET_ERR_MSG(extack, "knod: AES-GCM or ChaCha20-Poly1305, 16-byte ICV, only");
		return -EOPNOTSUPP;
	}
	key_bits = x->aead->alg_key_len;
	if (knod_ipsec_chacha(x)) {
		if (key_bits != 256 + 32) {
			NL_SET_ERR_MSG(extack, "knod: ChaCha20 takes a 256-bit key");
			return -EOPNOTSUPP;
		}
	} else if (key_bits != 128 + 32 && key_bits != 192 + 32 &&
		   key_bits != 256 + 32) {
		NL_SET_ERR_MSG(extack, "knod: AES-128, -192 or -256 only");
		return -EOPNOTSUPP;
	}
	return 0;
}

/*
 * A free slot among the ones @spi probes, or -1: none free, or one holding
 * the same SPI, which the engine could not tell apart.  Under ip->lock.
 */
static int knod_ipsec_slot(struct knod_ipsec *ip, u32 spi)
{
	u32 h = KNOD_PERSIST_IPSEC_SA_HASH(spi), i, k;
	int slot = -1;

	for (i = 0; i < KNOD_PERSIST_IPSEC_SA_PROBE; i++) {
		k = (h + i) & KNOD_IPSEC_SA_MASK;
		if (!ip->sa[k].x) {
			if (slot < 0)
				slot = k;
		} else if (knod_ipsec_spi(ip->sa[k].x) == spi) {
			return -1;
		}
	}
	return slot;
}

/*
 * @slot's entry but for spi and active: the salt, and the round keys and
 * H^1 .. H^KNOD_IPSEC_HPOW in a VRAM BO of the SA's own.
 */
/* ChaCha20-Poly1305's: the key's eight words in a BO, rounds 0. */
static int knod_ipsec_sa_install_chacha(struct knod_ipsec *ip, u32 slot,
					struct xfrm_state *x)
{
	struct knod_persistent_ipsec_sa __iomem *e = knod_ipsec_entry(ip, slot);
	const u8 *key = x->aead->alg_key;
	u32 __iomem *k;
	int i;

	ip->sa[slot].keys = knod_ipsec_alloc(ip->knod, 32);
	if (!ip->sa[slot].keys)
		return -ENOMEM;
	k = (u32 __iomem *)ip->sa[slot].keys->kaddr;
	for (i = 0; i < 8; i++)
		writel(get_unaligned_le32(key + 4 * i), &k[i]);
	writel(get_unaligned_le32(key + 32), &e->salt);
	writel(0, &e->rounds);
	writeq(ip->sa[slot].keys->gaddr, &e->rk);
	writeq(0, &e->hpow);
	knod_ipsec_publish(ip);
	return 0;
}

static int knod_ipsec_sa_install(struct knod_ipsec *ip, u32 slot,
				 struct xfrm_state *x,
				 struct netlink_ext_ack *extack)
{
	struct knod_persistent_ipsec_sa __iomem *e = knod_ipsec_entry(ip, slot);
	unsigned int key_len = x->aead->alg_key_len / 8 - 4;
	const u8 *key = x->aead->alg_key;
	struct crypto_aes_ctx *ctx;
	struct aes_enckey *enc;
	u32 __iomem *rk;
	be128 h, p;
	u64 hpow;
	int i, err;

	if (knod_ipsec_chacha(x))
		return knod_ipsec_sa_install_chacha(ip, slot, x);

	ctx = kmalloc_obj(*ctx, GFP_KERNEL);
	enc = kmalloc_obj(*enc, GFP_KERNEL);
	err = -ENOMEM;
	if (!ctx || !enc)
		goto out;
	err = aes_expandkey(ctx, key, key_len);
	if (!err)
		err = aes_prepareenckey(enc, key, key_len);
	if (err) {
		NL_SET_ERR_MSG(extack, "knod: bad AES key");
		goto out;
	}

	ip->sa[slot].keys = knod_ipsec_alloc(ip->knod, KNOD_IPSEC_KEYS_BYTES);
	if (!ip->sa[slot].keys) {
		err = -ENOMEM;
		goto out;
	}
	rk = (u32 __iomem *)ip->sa[slot].keys->kaddr;
	for (i = 0; i < 4 * (7 + key_len / 4); i++)
		writel(ctx->key_enc[i], &rk[i]);

	memset(&h, 0, sizeof(h));
	aes_encrypt(enc, (u8 *)&h, (u8 *)&h);
	p = h;
	hpow = KNOD_IPSEC_RK_BYTES;
	for (i = 0; i < KNOD_IPSEC_HPOW; i++) {
		if (i)
			gf128mul_lle(&p, &h);
		memcpy_toio((u8 __iomem *)rk + hpow + 16 * i, &p, sizeof(p));
	}

	writel(get_unaligned_le32(key + key_len), &e->salt);
	writel(6 + key_len / 4, &e->rounds);
	writeq(ip->sa[slot].keys->gaddr, &e->rk);
	writeq(ip->sa[slot].keys->gaddr + hpow, &e->hpow);
	knod_ipsec_publish(ip);
	memzero_explicit(&h, sizeof(h));
	memzero_explicit(&p, sizeof(p));
out:
	if (ctx)
		aes_zeroize_ctx(ctx);
	if (enc)
		aes_zeroize_enckey(enc);
	kfree(ctx);
	kfree(enc);
	return err;
}

static int knod_ipsec_state_add(struct knod_dev *knodev, struct xfrm_state *x,
				struct netlink_ext_ack *extack)
{
	struct knod_persistent_ipsec_sa __iomem *e;
	struct knod_ipsec *ip;
	int slot, err;
	u32 spi;

	err = knod_ipsec_validate(x, extack);
	if (err)
		return err;

	down_read(&knod_ipsec_rwsem);
	ip = knod_ipsec_of(knodev);
	if (!ip) {
		err = -EOPNOTSUPP;
		goto out;
	}
	spi = knod_ipsec_spi(x);
	spin_lock_bh(&ip->lock);
	slot = knod_ipsec_slot(ip, spi);
	if (slot >= 0)
		ip->sa[slot].x = x;
	spin_unlock_bh(&ip->lock);
	if (slot < 0) {
		NL_SET_ERR_MSG(extack, "knod: no SA slot for this SPI");
		err = -EOPNOTSUPP;
		goto out;
	}

	e = knod_ipsec_entry(ip, slot);
	writel(0, &e->active);
	knod_ipsec_publish(ip);
	err = knod_ipsec_sa_install(ip, slot, x, extack);
	if (err) {
		spin_lock_bh(&ip->lock);
		ip->sa[slot].x = NULL;
		spin_unlock_bh(&ip->lock);
		goto out;
	}
	writel(spi, &e->spi);
	knod_ipsec_publish(ip);
	writel(1, &e->active);
	knod_ipsec_publish(ip);

	x->xso.offload_handle = slot + 1;
	knod_ipsec_sa_set(knodev, slot, x);
	spin_lock_bh(&ip->lock);
	ip->nr_sa++;
	spin_unlock_bh(&ip->lock);
out:
	up_read(&knod_ipsec_rwsem);
	return err;
}

/* Under x->lock: the engine stops matching it, the slot stays taken. */
static void knod_ipsec_state_delete(struct knod_dev *knodev,
				    struct xfrm_state *x)
{
	struct knod_ipsec *ip = knod_ipsec_of(knodev);
	u32 slot = x->xso.offload_handle - 1;

	if (!ip || !x->xso.offload_handle || slot > KNOD_IPSEC_SA_MASK)
		return;
	writel(0, &knod_ipsec_entry(ip, slot)->active);
	/* Publish CPU BAR writes before the shader consumes them. */
	wmb();
	knod_ipsec_sa_set(knodev, slot, NULL);
}

/*
 * The slot back, once no wave can be decrypting with its keys: the queues
 * parked at a round boundary see the entry inactive from then on.
 */
static void knod_ipsec_state_free(struct knod_dev *knodev,
				  struct xfrm_state *x)
{
	struct knod_ipsec *ip = knod_ipsec_of(knodev);
	u32 slot = x->xso.offload_handle - 1;
	struct knod_ipsec_sa *sa;
	struct knod *knod;

	if (!ip || !x->xso.offload_handle || slot > KNOD_IPSEC_SA_MASK)
		return;
	knod = ip->knod;
	sa = &ip->sa[slot];
	if (sa->keys) {
		if (!knod_gda_pause(knod, KNOD_GDA_PAUSE_IPSEC_SA)) {
			knod_free_mem(knod, sa->keys);
			knod_gda_resume(knod);
		} else {
			pr_warn("knod: SA %u's keys kept, the queues did not park\n",
				slot);
		}
		sa->keys = NULL;
	}
	spin_lock_bh(&ip->lock);
	sa->x = NULL;
	ip->nr_sa--;
	spin_unlock_bh(&ip->lock);
	x->xso.offload_handle = 0;
}

/*
 * The inner checksum the NIC would have filled in, over the payload alone,
 * not the ESP trailer and ICV room past it.
 */
static int knod_ipsec_csum(struct sk_buff *skb, u32 icv)
{
	int start = skb_checksum_start_offset(skb);
	int field = start + skb->csum_offset;
	__wsum csum;
	int end;
	u8 pad;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;
	if (skb_copy_bits(skb, skb->len - icv - 2, &pad, 1))
		return -EINVAL;
	end = skb->len - icv - 2 - pad;
	if (start < 0 || end < field + 2 ||
	    skb_ensure_writable(skb, field + 2))
		return -EINVAL;
	csum = skb_checksum(skb, start, end - start, 0);
	*(__sum16 *)(skb->data + field) = csum_fold(csum) ?: CSUM_MANGLED_0;
	skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

/*
 * An outbound packet to the GPU to seal and send: always taken.  It is not
 * encrypted yet, so one the GPU cannot take is dropped, never sent.
 */
static bool knod_ipsec_xmit(struct knod_dev *knodev, struct sk_buff *skb,
			    struct xfrm_state *x)
{
	struct xfrm_offload *xo = xfrm_offload(skb);
	struct knod_ipsec *ip = knod_ipsec_of(knodev);
	u32 slot = x->xso.offload_handle - 1;
	u32 icv = x->aead->alg_icv_len / 8;
	int off = skb_transport_offset(skb);
	struct knod_gda *g;
	__be64 iv;
	u64 meta;

	g = ip ? ip->knod->gda : NULL;
	if (!g || !xo || skb_is_gso(skb) || slot > KNOD_IPSEC_SA_MASK ||
	    off < 0 || off + sizeof(struct ip_esp_hdr) + 8 + icv > skb->len ||
	    skb_ensure_writable(skb, off + sizeof(struct ip_esp_hdr) + 8))
		goto drop;
	/* The IV is the sequence number, as NICs that seal do. */
	iv = cpu_to_be64(xo->seq.low + ((u64)xo->seq.hi << 32));
	memcpy(skb->data + off + sizeof(struct ip_esp_hdr), &iv, sizeof(iv));
	if (knod_ipsec_csum(skb, icv))
		goto drop;
	meta = KNOD_PERSIST_HTX_ESP | (u64)slot << KNOD_PERSIST_HTX_SA_SHIFT |
	       (u64)off << KNOD_PERSIST_HTX_ESP_OFF_SHIFT;
	if (knod_gda_xmit(g, skb_get_queue_mapping(skb) % g->nr_queues, skb,
			  meta))
		goto drop;
	consume_skb(skb);
	return true;
drop:
	dev_core_stats_tx_dropped_inc(skb->dev);
	kfree_skb(skb);
	return true;
}

struct knod_accel_ipsec_ops knod_ipsec_accel_ops = {
	.state_add = knod_ipsec_state_add,
	.state_delete = knod_ipsec_state_delete,
	.state_free = knod_ipsec_state_free,
	.xmit = knod_ipsec_xmit,
};

/* T0 to T3: aes_enc_tab rotated left by 0, 8, 16 and 24 bits. */
static void knod_ipsec_ttab_fill(struct knod_ipsec *ip)
{
	u32 __iomem *t = (u32 __iomem *)ip->ttab->kaddr;
	int i, k;

	for (k = 0; k < 4; k++)
		for (i = 0; i < 256; i++)
			writel(rol32(aes_enc_tab[i], 8 * k), &t[256 * k + i]);
}

static void knod_ipsec_free(struct knod_ipsec *ip)
{
	if (ip->table)
		knod_free_mem(ip->knod, ip->table);
	if (ip->ttab)
		knod_free_mem(ip->knod, ip->ttab);
	kfree(ip);
}

/*
 * The receive kernel behind the IPsec engine, which the shader's next start
 * finds with the tables in the control block; then the NIC's xfrm states to
 * the accel.  knod_accel_ops.ipsec_ops has to be set already.
 */
int knod_ipsec_activate(struct knod *knod)
{
	struct knod_dev *knodev = knod->accel->knodev;
	struct knod_gda *g = knod->gda;
	struct knod_blob_callee callee;
	struct knod_ipsec *ip;
	const void *code;
	u32 size;
	int err;

	if (!g)
		return -ENODEV;
	ip = kzalloc_obj(*ip, GFP_KERNEL);
	if (!ip)
		return -ENOMEM;
	ip->knod = knod;
	spin_lock_init(&ip->lock);

	ip->engine.code = knod_blob_find_call(&knod->core_blob,
					      KNOD_BLOB_GDA_ENGINE_IPSEC,
					      g->fmt, &ip->engine.size,
					      &callee);
	ip->engine.call = callee.patch;
	ip->engine.lds_bytes = KNOD_PERSIST_GDA_IPSEC_LDS_BYTES;
	code = knod_blob_find(&knod->core_blob, KNOD_BLOB_GDA_RX_KERNEL, 0,
			      &size);
	if (!ip->engine.code || !ip->engine.call || !code) {
		pr_warn("knod: core blob has no IPsec engine for NIC format %u\n",
			g->fmt);
		err = -EOPNOTSUPP;
		goto err_free;
	}

	err = -ENOMEM;
	ip->ttab = knod_ipsec_alloc(knod, KNOD_PERSIST_GDA_IPSEC_TTAB_BYTES);
	ip->table = knod_ipsec_alloc(knod, KNOD_PERSIST_IPSEC_SA_MAX *
				     sizeof(struct knod_persistent_ipsec_sa));
	if (!ip->ttab || !ip->table)
		goto err_free;
	knod_ipsec_ttab_fill(ip);
	knod_ipsec_publish(ip);

	g->ipsec_ttab = ip->ttab->gaddr;
	g->ipsec_sa = ip->table->gaddr;
	g->ipsec_sa_mask = KNOD_IPSEC_SA_MASK;
	err = knod_gda_install(knod, code, size, 0, false, &ip->engine);
	if (err)
		goto err_tables;
	knod->ipsec = ip;

	err = knod_ipsec_attach(knodev);
	if (err)
		goto err_engine;
	return 0;

err_engine:
	knod->ipsec = NULL;
	if (knod_gda_install_default(knod)) {
		pr_warn("knod: IPsec engine left in place, its tables with it\n");
		return err;
	}
err_tables:
	g->ipsec_ttab = 0;
	g->ipsec_sa = 0;
	g->ipsec_sa_mask = 0;
err_free:
	knod_ipsec_free(ip);
	return err;
}

/* An SA still offloaded holds the feature on. */
bool knod_ipsec_busy(struct knod *knod)
{
	struct knod_ipsec *ip = knod->ipsec;
	bool busy;

	if (!ip)
		return false;
	spin_lock_bh(&ip->lock);
	busy = ip->nr_sa;
	spin_unlock_bh(&ip->lock);
	return busy;
}

/*
 * Under RTNL.  The states left, deleted and freed through the accel's ops
 * while they still stand in for the NIC's, as an unregister would; then the
 * NIC's ops back, and the core engine.
 */
void knod_ipsec_deactivate(struct knod *knod)
{
	struct knod_dev *knodev = knod->accel->knodev;
	struct knod_ipsec *ip = knod->ipsec;
	struct knod_gda *g = knod->gda;

	if (!ip)
		return;
	down_write(&knod_ipsec_rwsem);
	if (knod_ipsec_busy(knod))
		xfrm_dev_state_flush(dev_net(knodev->netdev), knodev->netdev,
				     true);
	WARN_ON(knod_ipsec_busy(knod));
	knod_ipsec_detach(knodev);
	knod->ipsec = NULL;
	up_write(&knod_ipsec_rwsem);

	g->ipsec_ttab = 0;
	g->ipsec_sa = 0;
	g->ipsec_sa_mask = 0;
	if (knod_gda_install_default(knod))
		pr_warn("knod: IPsec engine left in place, its tables with it\n");
	else
		knod_ipsec_free(ip);
}
#else
struct knod_accel_ipsec_ops knod_ipsec_accel_ops;

int knod_ipsec_activate(struct knod *knod)
{
	return -EOPNOTSUPP;
}

bool knod_ipsec_busy(struct knod *knod)
{
	return false;
}

void knod_ipsec_deactivate(struct knod *knod)
{
}
#endif

#include <sys/spu_printf.h>
#include <spu_intrinsics.h>
#include <sys/spu_thread.h>
#include <sys/spu_event.h>
#include <spu_mfcio.h>
#include "miniz.h"

// int 	spu_thread_receive_event (uint32_t spuq, uint32_t *data0, uint32_t *data1, uint32_t *data2)
// int 	spu_thread_send_event (uint8_t spup, uint32_t data0, uint32_t data1)

#define NAME_LEN 7
// #define NAME_LEN 50

#define SPUP 0x3E
#define SPUQ 0x3F

typedef uint32_t u32;

void unaligned_read(uint32_t ppu_addr, void *spu_addr, int bytes)
{
	uint8_t temp[2048] __attribute__ ((aligned(128)));
	uint32_t un = ppu_addr & 127;

	mfc_get(temp, (unsigned int) (ppu_addr - un), (bytes + un + 127) & ~127, 1, 0, 0);
	mfc_write_tag_mask(1 << 1);
	mfc_read_tag_status_all();

	memcpy(spu_addr, temp + un, bytes);
}

void unaligned_write(void *spu_addr, uint32_t ppu_addr, int bytes)
{
	uint8_t temp[2048] __attribute__ ((aligned(128)));
	uint32_t un = ppu_addr & 127;
	memcpy(temp + un, spu_addr, bytes);

	mfc_put(temp, (unsigned int)(ppu_addr - un), (bytes + un + 127) & ~127, 2, 0, 0);
	mfc_write_tag_mask(1 << 2);
	mfc_read_tag_status_all();
}

int slen(const char *s)
{
	int res = 0;
	for (; *s != '\0'; s += 1) { res += 1; }
	return res;
}

u32 sig_out_addr, sig_in_addr;

int init(void)
{
	u32 magic;
	spu_thread_receive_event(SPUQ, &magic, &sig_out_addr, &sig_in_addr);
	return magic == 0xDEFEC8ED;
}

int main(void)
{
	uint8_t data[NAME_LEN] = { 0 };
	mz_ulong data_len = NAME_LEN;
	u32 data0, data1, data2;
	u32 ppu_addr, ppu_len, ppu_out_addr, ppu_out_sig;

	if (!init())
	{
		goto exit;
	}

	for (;;)
  {
		spu_thread_receive_event(SPUQ, &data0, &data1, &data2);
		if (data0 == sig_out_addr)
		{
				ppu_out_addr = data1;
				ppu_out_sig = data2;
		}
		else if (data0 == sig_in_addr)
		{
				ppu_addr = data1;
				ppu_len = data2;

				uint8_t *buf = malloc(ppu_len + 2);
				buf[1] = 0x9c;
				unaligned_read(ppu_addr, buf + 2, ppu_len);
				buf[0] = 0x78;
				mz_uncompress(data, &data_len, buf, (mz_ulong)ppu_len);
				unaligned_write(data, ppu_out_addr, data_len);
				spu_thread_send_event(SPUP, ppu_out_sig, data_len);
				
				free(buf);
		}
	}

exit:
	spu_thread_exit(0);
	return 0;
}

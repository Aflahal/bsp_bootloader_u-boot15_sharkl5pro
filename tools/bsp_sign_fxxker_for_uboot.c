#define _CRT_SECURE_NO_WARNINGS
#define HASH_BYTE_LEN 32
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
typedef struct
{
	uint32_t mMagicNum;		  // "BTHD"=="0x42544844"=="boothead"
	uint32_t mVersion;		  // 1
	uint8_t mPayloadHash[32]; // sha256 hash value
	uint64_t mImgAddr;		  // image loaded address
	uint32_t mImgSize;		  // image size
	uint32_t is_packed;		  // packed image flag 0:false 1:true
	uint32_t mImgSizeOrig;
	uint8_t reserved2[16];
	uint32_t mFirmwareSize; // value = raw_ImgSize, mImgSize = (raw_ImgSize + 0xF) & 0xFFFFFFF0
	uint32_t mUnknownSize1; // value = header + mImgSize + footer + key_cert - 0x20 // for key_cert
							// value = header + mImgSize + footer + content_cert // for content_cert
	uint32_t mPostromFullSize;
	uint32_t mPostromOffset;
	uint8_t nickname[36];
	uint8_t reserved[384];
} sys_img_header;
#define ERR_EXIT(...)                 \
	do                                \
	{                                 \
		fprintf(stderr, __VA_ARGS__); \
		exit(1);                      \
	} while (0)
#define MAGIC_SIZE 8
typedef struct sprdsignedimageheader
{

	/* Magic number */
	uint8_t magic[MAGIC_SIZE];
	/* Version of this header format */
	uint32_t header_version_major;
	/* Version of this header format */
	uint32_t header_version_minor;

	/*image body, plain or cipher text */
	uint64_t payload_size;
	uint64_t payload_offset;

	/*offset from itself start */
	/*content certification size,if 0,ignore */
	uint64_t cert_size;
	uint64_t cert_offset;

	/*(opt)private content size,if 0,ignore */
	uint64_t priv_size;
	uint64_t priv_offset;

	/*(opt)debug/rma certification primary size,if 0,ignore */
	uint64_t cert_dbg_prim_size;
	uint64_t cert_dbg_prim_offset;

	/*(opt)debug/rma certification second size,if 0,ignore */
	uint64_t cert_dbg_developer_size;
	uint64_t cert_dbg_developer_offset;

} sprdsignedimageheader;

static uint8_t *sprd_get_sechdr_addr(uint8_t *buf)
{
	if (NULL == buf)
	{
		return NULL;
	}
	sys_img_header *imghdr = (sys_img_header *)buf;

	uint8_t *sechdr = buf + imghdr->mImgSize + sizeof(sys_img_header);
	return sechdr;
}

static uint8_t *loadfile(const char *fn, size_t *num, size_t extra)
{
	size_t n, j = 0;
	uint8_t *buf = 0;
	FILE *fi = fopen(fn, "rb");
	if (fi)
	{
		fseek(fi, 0, SEEK_END);
		n = ftell(fi);
		if (n)
		{
			fseek(fi, 0, SEEK_SET);
			buf = (uint8_t *)malloc(n + extra);
			if (buf)
				j = fread(buf, 1, n, fi);
		}
		fclose(fi);
	}
	if (num)
		if (extra)
			*num = ((j + extra - 1) / extra) * extra;
		else
			*num = j;
	return buf;
}
#define MULTI_HEADER 1
int chsize(char *filename)
{
	uint8_t *mem;
	size_t size = 0;
	mem = loadfile(filename, &size, 0);
	if (!mem)
		ERR_EXIT("loadfile(\"%s\") failed\n", filename);
	if ((uint64_t)size >> 32)
		ERR_EXIT("file too big\n");

	if (*(uint32_t *)mem != 0x42544844)
		ERR_EXIT("The file is not sprd trusted firmware\n");
	else if (!(*(uint32_t *)&mem[0x30]))
		ERR_EXIT("broken sprd trusted firmware\n");
	if (*(uint32_t *)&mem[0x30] + 0x260 >= size)
	{
		printf("0x%zx\n", size);
		free(mem);
		return 0;
	}
	if (*(uint32_t *)&mem[(*(uint32_t *)&mem[0x30]) + 0x200 + 0x50] && *(uint32_t *)&mem[(*(uint32_t *)&mem[0x30]) + 0x200 + 0x58])
		size = *(uint32_t *)&mem[(*(uint32_t *)&mem[0x30]) + 0x200 + 0x50] + *(uint32_t *)&mem[(*(uint32_t *)&mem[0x30]) + 0x200 + 0x58];
	else if (*(uint32_t *)&mem[(*(uint32_t *)&mem[0x30]) + 0x200 + 0x30] && *(uint32_t *)&mem[(*(uint32_t *)&mem[0x30]) + 0x200 + 0x38])
		size = *(uint32_t *)&mem[(*(uint32_t *)&mem[0x30]) + 0x200 + 0x30] + *(uint32_t *)&mem[(*(uint32_t *)&mem[0x30]) + 0x200 + 0x38];
	else if (*(uint32_t *)&mem[(*(uint32_t *)&mem[0x30]) + 0x200 + 0x20] && *(uint32_t *)&mem[(*(uint32_t *)&mem[0x30]) + 0x200 + 0x28])
		size = *(uint32_t *)&mem[(*(uint32_t *)&mem[0x30]) + 0x200 + 0x20] + *(uint32_t *)&mem[(*(uint32_t *)&mem[0x30]) + 0x200 + 0x28];
	else
		size = *(uint32_t *)&mem[0x30] + 0x200;
	printf("0x%zx\n", size);

	FILE *file = fopen("temp", "wb");
	if (file == NULL)
		ERR_EXIT("Failed to create the file.\n");
	size_t bytes_written = fwrite(mem, sizeof(unsigned char), size, file);
	if (bytes_written != size)
		ERR_EXIT("Failed to write the file.\n");
	fclose(file);

	if (remove(filename))
		ERR_EXIT("Failed to delete the file.\n");
	if (rename("temp", filename))
		ERR_EXIT("Failed to rename the file.\n");
	free(mem);

	return 0;
}

int32_t decode_bcond_offset(uint32_t inst)
{
	int32_t imm19 = (inst >> 5) & 0x7FFFF;
	if (imm19 & (1 << 18))
		imm19 |= ~0x7FFFF;
	return imm19 << 2;
}

// [FFFF0071]
// FFFF40B9 FFFF0891 FFFFFF54
void patch_code(uint8_t *mem, size_t size)
{
	int delta = 0;
	size_t pos_cmp = 0, pos_ldr = 0, pos_add = 0, pos_bne = 0;
	for (size_t i = 0x200; i < size; i += 4)
	{
		uint32_t current = *(uint32_t *)&mem[i];
		if (current == 0xD65F03C0 || (current & 0xFF00FFFF) == 0xA8007BFD)
		{
			pos_cmp = 0, pos_ldr = 0, pos_add = 0, pos_bne = 0;
		}
		else if ((current & 0xFFFF0000) == 0xB9400000)
		{
			if (((current >> 10) & 0xFFF) == 0xC)
			{
				pos_ldr = i;
				pos_cmp = 0, pos_add = 0, pos_bne = 0;
				int reg_ldr = current & 0x1F;
				for (size_t m = pos_ldr - 0x80; m < pos_ldr + 0x80; m += 4)
				{
					uint32_t current = *(uint32_t *)&mem[m];
					if ((current & 0xFFFF0000) == 0x71000000)
					{
						if (((current >> 10) & 0xFFF) == 1)
							pos_cmp = m;
					}
					else if ((current & 0xFFFF0000) == 0x91080000)
					{
						int reg_add = (current >> 5) & 0x1F;
						if (reg_ldr == reg_add)
							pos_add = m;
					}
					else if (pos_add && (current & 0xFF000000) == 0x54000000)
					{
						pos_bne = m;
					}
					if (pos_cmp && pos_bne)
					{
						printf("cmp 0x%x, ldr 0x%x, add 0x%x, bne 0x%x\n", pos_cmp, pos_ldr, pos_add, pos_bne);
						current = *(uint32_t *)&mem[pos_ldr];
						current &= ~(0xFFF << 10);
						current |= (0xE << 10);
						*(uint32_t *)&mem[pos_ldr] = current;
						current = *(uint32_t *)&mem[pos_bne];
						current = decode_bcond_offset(current);
						*(uint32_t *)&mem[pos_bne] = 0x14000000 + current / 4;
						break;
					}
				}
			}
		}
	}
}

int main(int argc, char **argv)
{
	printf("bsp_sign_fucker_for_uboot by YC & QuTick102\n");
	if (argc < 4)
		ERR_EXIT("Usage: %s <path_to_orig_sml_teecfg> <path_to_orig_uboot> <path_to_save_bspbypassed_file>\n", argv[0]);

	size_t signed_img_size = 0, modified_img_size = 0;
	chsize(argv[1]);
	uint8_t *signed_img = loadfile(argv[1], &signed_img_size, 0),
			*modified_img = loadfile(argv[2], &modified_img_size, 16),
			*out_put_file = NULL;

	if (!signed_img || !modified_img)
		ERR_EXIT("load files failed\n");

	patch_code(modified_img, modified_img_size);
	size_t orig_signed_img_size = (*(uint32_t *)&signed_img[0x30]);

	if (*(uint32_t *)signed_img != 0x42544844 || !orig_signed_img_size)
		ERR_EXIT("The file is not sprd trusted firmware\n");

	signed_img_size -= sizeof(sys_img_header);
#if MULTI_HEADER
	size_t modified_img_headers_size = 0;
#endif
	size_t orig_modified_img_size = *(uint32_t *)&modified_img[0x30];
	if (*(uint32_t *)modified_img == 0x42544844 && orig_modified_img_size)
	{
#if MULTI_HEADER
		modified_img_headers_size = modified_img_size - orig_modified_img_size - sizeof(sys_img_header);
#endif
		modified_img_size = orig_modified_img_size;
		modified_img += sizeof(sys_img_header);
	}

#if MULTI_HEADER
	if (!(out_put_file = (uint8_t *)malloc(sizeof(sys_img_header) + modified_img_size + modified_img_headers_size + signed_img_size)))
		ERR_EXIT("malloc failed\n");
#else
	if (!(out_put_file = (uint8_t *)malloc(sizeof(sys_img_header) + modified_img_size + signed_img_size)))
		ERR_EXIT("malloc failed\n");
#endif

	sys_img_header sys_img_hdr = *(sys_img_header *)signed_img;
	sprdsignedimageheader *img_hdr = (sprdsignedimageheader *)sprd_get_sechdr_addr(signed_img);

	signed_img += sizeof(sys_img_header);

#if MULTI_HEADER
	memcpy(out_put_file + sizeof(sys_img_header) + modified_img_size, modified_img + modified_img_size, modified_img_headers_size);

	sys_img_hdr.mImgSize += modified_img_size + modified_img_headers_size;
	sys_img_hdr.mImgSizeOrig = orig_modified_img_size;
	img_hdr->payload_offset += modified_img_size + modified_img_headers_size;
	img_hdr->cert_offset += modified_img_size + modified_img_headers_size;
#else
	sys_img_hdr.mImgSize += modified_img_size;
	img_hdr->payload_offset += modified_img_size;
	img_hdr->cert_offset += modified_img_size;
#endif

	memcpy(out_put_file, &sys_img_hdr, sizeof(sys_img_header));
	memcpy(out_put_file + sizeof(sys_img_header), modified_img, modified_img_size);
#if MULTI_HEADER
	memcpy(out_put_file + sizeof(sys_img_header) + modified_img_size + modified_img_headers_size, signed_img, signed_img_size);
#else
	memcpy(out_put_file + sizeof(sys_img_header) + modified_img_size, signed_img, signed_img_size);
#endif

#if MULTI_HEADER
	fwrite(out_put_file, 1, sizeof(sys_img_header) + modified_img_size + modified_img_headers_size + signed_img_size, fopen(argv[3], "wb"));
#else
	fwrite(out_put_file, 1, sizeof(sys_img_header) + modified_img_size + signed_img_size, fopen(argv[3], "wb"));
#endif
	return 0;
}
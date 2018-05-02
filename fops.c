#include "fops.h"

static FILE *fops_fok(FILE *fp) {
	return ((FILE*) fp);
}

static FILE *fops_fopen(const char *path, const char *mode) {
	return fopen(path,mode);
}

static int fops_fclose(FILE *fp) {
	assert(fops_fok(fp));
	fclose(fp);
	fp = NULL;
	return 0;
}

static size_t fops_fsize(FILE *fp) {
	assert(fops_fok(fp));
	size_t size;
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	return size;
}
static unsigned char *fops_fread(FILE *fp) {
	assert(fops_fok(fp));

	size_t size = fops_fsize(fp);

	unsigned char *data = (unsigned char*) malloc(sizeof(unsigned char) * size);

	assert(fread(data, 1, size, fp) == size);
	return data;
}

static void fops_fwrite(FILE *fp, FOPS_TYPE input) {
	assert(fops_fok(fp));
	assert(fwrite(input.data, 1, input.length, fp) == input.length);
}

FOPS_TYPE fops_read(char *path) {
	FOPS_TYPE tmp_file;

	FILE *fp = fops_fopen(path, "r");
	assert(fops_fok(fp));

	tmp_file.length = fops_fsize(fp);
	tmp_file.data = fops_fread(fp);

	fops_fclose(fp);
	return tmp_file;
}

void fops_write(char *path, FOPS_TYPE input) {
	FILE *fp = fops_fopen(path, "w");
	assert(fops_fok(fp));

	fops_fwrite(fp, input);
}

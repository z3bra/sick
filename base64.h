#ifndef BASE64_H__
#define BASE64_H__

uint8_t base64_index(const char *base64, char ch);
size_t base64_encode(char **buf, const unsigned char *msg, size_t len);
size_t base64_decode(char **buf, const unsigned char *msg, size_t len);
size_t base64_fold(FILE *out, char *msg, size_t len, size_t fold);

#endif

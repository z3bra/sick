#ifndef BASE64_H__
#define BASE64_H__

size_t base64_encode(char **buf, const unsigned char *msg, size_t len);
size_t base64_decode(char **buf, const unsigned char *msg, size_t len);

const char base64_table[] = {
	'A','B','C','D','E','F','G','H','I','J','K','L','M',
	'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
	'a','b','c','d','e','f','g','h','i','j','k','l','m',
	'n','o','p','q','r','s','t','u','v','w','x','y','z',
	'0','1','2','3','4','5','6','7','8','9','+','/'
};

#endif

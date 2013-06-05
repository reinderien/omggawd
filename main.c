#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <json/json.h>

static int codeindex = 0;
static void parseBody(char *body) {
	static const char btag[] = "<code>", etag[] = "</code>";
	int oldindex = codeindex;

	for (;; codeindex++) {
		// Parse out a single code nugget
		char *begin = strstr(body, btag);
		if (!begin) break;
		char *content = begin + sizeof(btag) - 1;
		char *end = strstr(content, etag);
		if (!end) break;
		*end = '\0';

		char filename[1024];
		snprintf(filename, sizeof(filename), "code/nugget_%d.c", codeindex);
		FILE *nug = fopen(filename, "w");
		assert(nug);
		fputs(content, nug);
		fclose(nug);

		body = end + sizeof(etag) - 1;
	}

	printf("Parsed code nuggets: %d new, %d total\n",
		codeindex - oldindex, codeindex);
}

static CURLcode curlerr(CURLcode errornum, const char *cmd) {
	if (errornum != CURLE_OK)
		fprintf(stderr, "cURL error %d from %s: %s\n",
			errornum, cmd, curl_easy_strerror(errornum));
	return errornum;
}
#define CURLERR(cmd) curlerr(cmd, #cmd)

// Stream in from cURL to the JSON parser
static struct json_tokener *jtok;
static struct json_object *jo;
static size_t writecurl(char *ptr, size_t size, size_t nmemb, void *userdata) {
	size_t newbytes = size*nmemb;

	jo = json_tokener_parse_ex(jtok, ptr, newbytes);
	enum json_tokener_error jerr = json_tokener_get_error(jtok);
	if (!((jo && jerr == json_tokener_success) ||
		 (!jo && jerr == json_tokener_continue))) {
		fprintf(stderr, "\nJSON error %d: %s\n", 
			jerr, json_tokener_error_desc(jerr));
		return 0;
	}
	return newbytes;
}

// jSON field helper
#define JO(field, type, jotype) \
type field = 0; { \
	struct json_object *innerjo = json_object_object_get(ojo, #field); \
	if (innerjo) \
		field = json_object_get_##jotype(innerjo); \
}

#define JO_INT(field) JO(field, int, int)
#define JO_STR(field) JO(field, const char*, string)

static CURL *curl;
static bool getCode(int page, int pagesize, const char *tag) {
	json_tokener_reset(jtok);

	char url[1024];
	snprintf(url, sizeof(url),
		"http://api.stackexchange.com/2.1/search/advanced?"
		"page=%d&pagesize=%d&tagged=%s&"
		"site=stackoverflow&filter=!g)vqRDxpLR(dV",
		page, pagesize, tag);
		
	assert(!CURLERR(curl_easy_setopt(curl, CURLOPT_URL, url)));
	if (CURLERR(curl_easy_perform(curl)))
		return true;
	
	struct json_object *ojo = jo;

	JO_INT(error_id);
	if (error_id) {
		JO_STR(error_name);
		JO_STR(error_message);
		fprintf(stderr, "\nSO JSON error %d: %s (%s)\n",
			error_id, error_name, error_message);
		return false;
	}

	JO_INT(total);
	JO_INT(quota_remaining);
	JO_INT(quota_max);
	JO_INT(backoff);
	JO_STR(has_more);
	bool bhas_more = !strcmp("true", has_more);

	printf("page %d; items %d-%d of %d; quota %d/%d (%d%%); backoff %d; %s more \n", // \r
		page,
		1 + (page - 1)*pagesize, page*pagesize, total,
		quota_remaining, quota_max, quota_remaining*100/quota_max,
		backoff,
		has_more ? "has" : "no");
	fflush(stdout);

	struct json_object *jitems = json_object_object_get(jo, "items");
	if (jitems) {
		int nitems = json_object_array_length(jitems);
		for (int i = 0; i < nitems; i++) {
			ojo = json_object_array_get_idx(jitems, i);
			JO_STR(body);
			// const? pffft
			parseBody((char*)body);
		}
	}

	json_object_put(jo); // put = release

	if (!bhas_more || !quota_remaining)
		return false;
	if (backoff)
		sleep(backoff);
	return true;
}

void stomp_everything();

int main() {
	curl = curl_easy_init();
	assert(curl);
	assert(!CURLERR(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writecurl)));
	assert(!CURLERR(curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip")));

	jtok = json_tokener_new();
	assert(jtok);

	//for (
	    int p = 1;
	    getCode(p, 10, "c"); // p++);

	json_tokener_free(jtok);
	curl_easy_cleanup(curl);

	// testall();

	// stomp_everything();

	return 0;
}

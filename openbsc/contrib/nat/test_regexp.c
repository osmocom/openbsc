/* make test_regexp */
#include <sys/types.h>
#include <regex.h>
#include <stdio.h>


int main(int argc, char **argv)
{
	regex_t reg;
	regmatch_t matches[2];

	if (argc != 4) {
		printf("Invoke with: test_regexp REGEXP REPLACE NR\n");
		return -1;
	}

	if (regcomp(&reg, argv[1], REG_EXTENDED) != 0) {
		fprintf(stderr, "Regexp '%s' is not valid.\n", argv[1]);
		return -1;
	}

	if (regexec(&reg, argv[3], 2, matches, 0) == 0 && matches[1].rm_eo != -1)
		printf("New Number: %s%s\n", argv[2], &argv[3][matches[1].rm_so]);
	else
		printf("No match.\n");

	regfree(&reg);

	return 0;
}

#ifdef MISDN_OLD_AF_COMPATIBILITY
#undef AF_ISDN
#undef PF_ISDN

extern	int	AF_ISDN;
#define PF_ISDN	AF_ISDN

int	AF_ISDN;

#endif

extern void init_af_isdn(void);

#ifdef AF_COMPATIBILITY_FUNC
#ifdef MISDN_OLD_AF_COMPATIBILITY
void init_af_isdn(void)
{
	int	s;

	/* test for new value */
	AF_ISDN = 34;
	s = socket(AF_ISDN, SOCK_RAW, ISDN_P_BASE);
	if (s >= 0) {
		close(s);
		return;
	}
	AF_ISDN = 27;
	s = socket(AF_ISDN, SOCK_RAW, ISDN_P_BASE);
	if (s >= 0) {
		close(s);
		return;
	}
}
#else
void init_af_isdn(void)
{
}
#endif
#endif

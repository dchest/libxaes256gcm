.PHONY: all test benchmark lib clean format

all test benchmark lib clean:
	@os=`uname -s`; \
	case "$$os" in \
		Darwin)  submake=Makefile.apple ;; \
		OpenBSD) submake=Makefile.libressl ;; \
		*)       submake=Makefile.openssl ;; \
	esac; \
	$(MAKE) -f $$submake $@

format:
	clang-format -i *.c *.h

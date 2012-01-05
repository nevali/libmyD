LIBOUT = libmyD.a
LIBOBJ = pem.o structure.o traverse.o policy.o

OUT = myd-verify
OBJ = verify.o

srcdir ?= .

REDLAND_CFLAGS := `pkg-config --cflags redland`
REDLAND_LIBS := `pkg-config --libs redland`

OPENSSL_CFLAGS := `pkg-config --cflags libcrypto`
OPENSSL_LIBS := `pkg-config --libs libcrypto`


INCLUDES = -I$(srcdir)/include
CPPFLAGS = -W -Wall $(DEFS) $(INCLUDES) $(REDLAND_CFLAGS) $(OPENSSL_CFLAGS)
CFLAGS =  -g $(CPPFLAGS)

CCLD = $(CC)
LDFLAGS =
LIBS = $(REDLAND_LIBS) $(OPENSSL_LIBS)

all: $(LIBOUT) $(OUT)

clean:
	rm -f $(OUT) $(OBJ)
	rm -f $(LIBOUT) $(LIBOBJ)

$(LIBOUT): $(LIBOBJ)
	$(AR) rcs $(LIBOUT) $(LIBOBJ)

$(OUT): $(OBJ) $(LIBOUT)
	$(CCLD) $(LDFLAGS) -o $(OUT) $(OBJ) $(LIBOUT) $(LIBS)

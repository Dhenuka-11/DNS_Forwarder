CC = gcc
CFLAGS = -Wall -O2
LIBS = -lcurl

TARGET = dns_forwarder
SRC = dns_forwarder.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)


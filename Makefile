all: record

record: record.c
	gcc record.c -o record -lpcap

rm: record
	rm record
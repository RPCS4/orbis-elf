%.o: %.c
	@echo "CC      $@"
	$(CC) $(CFLAGS) -c $< -o $@

%.a:
	@echo "AR      $@"
	$(AR) $(ARFLAGS) $@ $^

%: %.o
	@echo "LD      $@"
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

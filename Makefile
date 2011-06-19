APP=wrapper
 
LIBDIR := $(ANDROID_NDK_ROOT)/toolchains/arm-eabi-4.4.0/prebuilt/linux-x86/lib
SYSROOT := $(ANDROID_NDK_ROOT)/platforms/android-9/arch-arm/

#TOOLCHAIN_PREFIX := arm-eabi-
CC := $(TOOLCHAIN_PREFIX)gcc
CPP := $(TOOLCHAIN_PREFIX)g++
LD := $(CC)
COMMON_FLAGS := -mandroid -ffunction-sections -fdata-sections -Os -g \
	--sysroot=$(SYSROOT) \
	-fPIC \
	-fvisibility=hidden \
	-D__NEW__
 
CFLAGS := $(COMMON_FLAGS)

INCLUDE := -I. -I../include/ -I$(ANDROID_NDK_ROOT)/platforms/android-9/arch-arm/usr/include/
 
CFLAGS += -g -D__ARM_ARCH_5__ -D__ARM_ARCH_5T__ -D__ARM_ARCH_5E__ -D__ARM_ARCH_5TE__ -DANDROID -DSK_RELEASE -DNDEBUG
 
CFLAGS += -UDEBUG -march=armv5te -mtune=xscale -msoft-float -mthumb-interwork -fpic -ffunction-sections -funwind-tables -fstack-protector -fmessage-length=0 -Bdynamic
 
CPPFLAGS := $(COMMON_FLAGS) \
	-fno-rtti -fno-exceptions \
	-fvisibility-inlines-hidden 
LDFLAGS += --sysroot=$(SYSROOT)
LDFLAGS +=  -Bdynamic -Wl,-dynamic-linker,/system/bin/linker -Wl,--gc-sections -Wl,-z,nocopyreloc 
LDFLAGS += -L$(LIBDIR)/gcc/arm-eabi/4.4.0/
LDFLAGS += -L$(LIBDIR)/gcc/
LDFLAGS += -L$(LIBDIR)
LDFLAGS += -L$(ANDROID_NDK_ROOT)/platforms/android-8/arch-arm/usr/lib/
LDFLAGS += -nostdlib -lc -llog -lgcc\
	--no-undefined -z $(SYSROOT)/usr/lib/crtbegin_dynamic.o $(SYSROOT)/usr/lib/crtend_android.o 
LIBS += "-lc -lpthread"
APP_OBJS = $(APP).o ether_aton.o
all:    $(APP)

$(APP): $(APP_OBJS) $(LIBDIR)/gcc/arm-eabi/4.4.0/libgcc.a
	$(LD) $(LDFLAGS) -o $@ $^ 

%.o:    %.c 
	$(CC) -c $(INCLUDE) $(CFLAGS) $< -o $@ 
 
%.o:    %.cpp 
	$(CPP) -c $(CFLAGS) $(CPPFLAGS) $< -o $@ 
 
install: $(APP)
	adb push $(APP) /data/local/bin/$(APP) 
	adb shell chmod 755 /data/local/bin/$(APP1) 
run: 
	$(SDKTOOL)/adb shell /data/local/bin/$(APP1) 
 
clean: 
	@rm -f $(APP) *.o

AM_CPPFLAGS = -Wall
AM_CFLAGS   =
AM_CXXFLAGS =
AM_LDFLAGS  =

# protobuf
AM_CPPFLAGS += $(PROTOBUF_CFLAGS)
AM_LDFLAGS  += $(PROTOBUF_LIBS)
# grpc
AM_CPPFLAGS += $(GRPC_CFLAGS)
AM_LDFLAGS  += $(GRPC_LIBS)

check_PROGRAMS =

# grpc integrate with automake is copyed from answer in the following link
# https://stackoverflow.com/questions/13939904/how-to-use-protocol-buffers-with-autoconf-automake

check_PROGRAMS += test-grpc
test_grpc_SOURCES = test-grpc.cc
test_grpc_SOURCES += $(builddir)/demo.pb.cc $(builddir)/demo.pb.h
test_grpc_SOURCES += $(builddir)/demo.grpc.pb.cc $(builddir)/demo.grpc.pb.h
BUILT_SOURCES = demo.pb.cc demo.pb.h
BUILT_SOURCES += demo.grpc.pb.cc demo.grpc.pb.h

%.grpc.pb.cc %.grpc.pb.h: %.proto
	$(AM_V_GEN) $(PROTOC) -I$(srcdir) --grpc_out=$(builddir) --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN) $^
%.pb.cc %.pb.h: %.proto
	$(AM_V_GEN) $(PROTOC) -I$(srcdir) --cpp_out=$(builddir) $^

TESTS = $(check_PROGRAMS)

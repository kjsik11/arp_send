TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += \
        input_ip.cpp \
        input_mac.cpp \
        main.cpp \
        struct.cpp

HEADERS += \
    main.h

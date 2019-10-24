JNA := jna-5.2.0.jar

all: FancyJIT.class libcompiler.so

run: all
		java -Xmx200m -cp ${JNA}:. FancyJIT

compiler: compiler.c
		gcc compiler.c -Wall -o compiler

FancyJIT.class: FancyJIT.java ${JNA}
		javac -cp ${JNA} FancyJIT.java

libcompiler.so: compiler.c
		gcc -fPIC compiler.c -shared -o libcompiler.so

${JNA}:
		wget https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.2.0/jna-5.2.0.jar

clean:
		rm -rf *.class ${JNA} libcompiler.so


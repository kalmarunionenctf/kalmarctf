FROM labsai/eddi:latest

# Switch to root user so we can install packages
USER root 
RUN microdnf install -y zip

# Define some variables we'll use
ENV JAR_NAME="org.eclipse.microprofile.openapi.microprofile-openapi-api-4.0.2.jar"
ENV JAVA_DIR="org/eclipse/microprofile/openapi/annotations/enums/"
ENV JAVA_NAME="org/eclipse/microprofile/openapi/annotations/enums/Explode.java"
ENV CLASS_NAME="org/eclipse/microprofile/openapi/annotations/enums/Explode.class"
ENV OUT_DIR="/deployments/lib/main/out/"

# Prepare
WORKDIR /deployments/lib/main
RUN mkdir $OUT_DIR
    
# Compile `Explode.class`
RUN mkdir -p $JAVA_DIR
COPY ./Explode.java $JAVA_NAME
RUN javac $JAVA_NAME

# Overwrite `Explode.class` in jarfile
RUN zip $JAR_NAME $CLASS_NAME

# Overwrite ENTRYPOINT so the jar is copied to our mounted working directory on the host
ENTRYPOINT cp $JAR_NAME "$OUT_DIR$JAR_NAME"
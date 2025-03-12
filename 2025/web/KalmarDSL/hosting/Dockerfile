# Build read flag binary
FROM gcc:latest AS gccbuilder
WORKDIR /
COPY would.c /
RUN gcc -o would would.c

# Build challenge WAR file
FROM gradle:jdk17-noble AS gradlebuilder
WORKDIR /
RUN git clone https://github.com/structurizr/ui.git structurizr-ui
RUN git clone https://github.com/structurizr/onpremises.git structurizr-onpremises
WORKDIR /structurizr-onpremises
# Target: structurizr/onpremises v3.1.0
RUN git reset --hard c11ff7c3986529839ba4cf9c6fd9efa3b9045f1c
RUN echo 'structurizrVersion=3.1.0' > gradle.properties
# Fix 'bug' in structurizr/onpremises: the !script tag didn't work.
RUN sed -i '/^dependencies/a \    implementation "org.jruby:jruby-core:9.4.12.0"' structurizr-onpremises/build.gradle
RUN bash ./ui.sh
RUN ./gradlew clean build -x integrationTest

# Challenge Dockerfile
FROM tomcat:10.1.35-jre21-temurin-noble
ENV PORT=8080

# Switch to root user so we can add a getflag SUID binary
USER root
WORKDIR /
COPY --from=gccbuilder /would /would
COPY flag.txt /
RUN chmod 400 /flag.txt && chmod 6111 /would

# ... you're welcome!
RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends ncat

# Hardening against unintended boring read-any-file bugs
RUN groupadd -r tomcatgroup && useradd -r -m -g tomcatgroup tomcatuser
RUN chown -R tomcatuser:tomcatgroup /usr/local/tomcat
USER tomcatuser

COPY --from=gradlebuilder /structurizr-onpremises/structurizr-onpremises/build/libs/structurizr-onpremises.war /usr/local/tomcat/webapps/ROOT.war

EXPOSE 8080

CMD ["catalina.sh", "run"]

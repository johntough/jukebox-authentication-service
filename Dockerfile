FROM openjdk:19-jdk

# Create a custom user with UID 1234 and GID 1234
RUN groupadd -g 1234 customgroup && \
    useradd -m -u 1234 -g customgroup customuser

# Switch to the custom user
USER customuser

WORKDIR /app

COPY target/jukebox-authentication-service-0.0.1-SNAPSHOT.jar /app/jukebox-authentication-service-0.0.1-SNAPSHOT.jar

EXPOSE 3001

CMD ["java", "-jar", "/app/jukebox-authentication-service-0.0.1-SNAPSHOT.jar"]
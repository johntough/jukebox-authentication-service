# Step 1: Use an official OpenJDK base image from Docker Hub
FROM openjdk:19-jdk

# Step 2: Set the working directory inside the container
WORKDIR /app

# Step 3: Copy the Spring Boot JAR file into the container
COPY ../target/jukebox-authentication-service-0.0.1-SNAPSHOT.jar /app/jukebox-authentication-service-0.0.1-SNAPSHOT.jar

# Step 4: Expose the port your application runs on
EXPOSE 3001

# Step 5: Define the command to run your Spring Boot application
CMD ["java", "-jar", "/app/jukebox-authentication-service-0.0.1-SNAPSHOT.jar"]
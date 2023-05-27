FROM openjdk:17-oracle
WORKDIR /students-auth
COPY /target/studentes-0.0.1-SNAPSHOT.jar .
CMD ["java", "-jar", "studentes-0.0.1-SNAPSHOT.jar"]
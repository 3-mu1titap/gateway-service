
FROM openjdk:17-jdk-slim

WORKDIR /app

COPY build/libs/gateway-0.0.1-SNAPSHOT.jar gateway-service.jar

EXPOSE 8000

ENTRYPOINT ["java", "-jar", "gateway-service.jar"]

ENV TZ=Asia/Seoul
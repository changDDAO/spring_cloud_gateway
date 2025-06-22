FROM amazoncorretto:17
LABEL authors="changhoyoun"

ARG JAR_FILE=build/libs/*.jar
COPY ${JAR_FILE} spring_cloud_gateway.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/spring_cloud_gateway.jar"]
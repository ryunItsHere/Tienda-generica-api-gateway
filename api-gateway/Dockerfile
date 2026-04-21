# ETAPA 1: Compilación (Build)
FROM maven:3.8.5-openjdk-17-slim AS build
WORKDIR /app

# Copiamos el archivo de configuración de dependencias
COPY pom.xml .
# Descargamos las dependencias (esto acelera futuras compilaciones)
RUN mvn dependency:go-offline

# Copiamos el código fuente y compilamos el proyecto saltando los tests
COPY src ./src
RUN mvn clean package -DskipTests

# ETAPA 2: Ejecución (Runtime)
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Copiamos el archivo .jar generado en la etapa anterior
# Nota: Asegúrate de que el nombre coincida con el de tu pom.xml o usa un comodín
COPY --from=build /app/target/*.jar app.jar

# Exponemos el puerto que usa el Gateway (según tus docs es el 8080 u 8081)
EXPOSE 8080

# Comando para iniciar el microservicio
ENTRYPOINT ["java", "-jar", "app.jar"]
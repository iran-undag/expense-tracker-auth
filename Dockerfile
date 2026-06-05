# Stage 1: Build
FROM maven:3.9-eclipse-temurin-17-alpine AS builder

WORKDIR /app

COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY . .
RUN mvn clean package -DskipTests

# Stage 2: Runtime
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

RUN apk add --no-cache curl netcat-openbsd
RUN addgroup -g 1001 appuser && adduser -D -u 1001 -G appuser appuser

COPY --from=builder /app/target/*.jar app.jar
COPY scripts/wait-for-db.sh /app/wait-for-db.sh

RUN mkdir -p /app/logs /app/secrets \
    && chmod +x /app/wait-for-db.sh \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -fsS http://localhost:9000/actuator/health || exit 1

ENTRYPOINT ["/app/wait-for-db.sh", "java", "-jar", "app.jar"]

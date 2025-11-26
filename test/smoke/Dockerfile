FROM alpine

# Встановлюємо curl
RUN apk add --no-cache curl

# Створюємо непривілейованого користувача
RUN addgroup -S juice && adduser -S juice -G juice

# Копіюємо файли та призначаємо їх непривілейованому користувачу
COPY smoke-test.sh /home/juice/smoke-test.sh
RUN chown juice:juice /home/juice/smoke-test.sh
RUN chmod +x /home/juice/smoke-test.sh

# Переходимо на непривілейованого користувача
USER juice

# Вказуємо робочу директорію
WORKDIR /home/juice

CMD ["sh", "smoke-test.sh", "http://app:3000"]

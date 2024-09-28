import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';
import {config} from 'dotenv'
config()


async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // Set up microservice
  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.RMQ,
    options: {
      urls: [configService.get<string>('RABBITMQ_URL')],
      queue: 'auth_queue',
      queueOptions: {
        durable: false
      },
    },
  });

  
  // Set up HTTP listener
  await app.startAllMicroservices();
  await app.listen(configService.get<number>('AUTH_SERVICE_PORT') || 3002);
}
bootstrap();

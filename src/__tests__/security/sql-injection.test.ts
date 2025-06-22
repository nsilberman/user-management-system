import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../app.module';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../../models/user.entity';
import { Repository } from 'typeorm';

describe('SQL Injection Prevention Tests', () => {
  let app: INestApplication;
  let repository: Repository<User>;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    repository = moduleFixture.get<Repository<User>>(getRepositoryToken(User));
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(async () => {
    await repository.clear();
  });

  const maliciousInputs = [
    "'; DROP TABLE users; --",
    "' OR '1'='1",
    "'; INSERT INTO users (email) VALUES ('hacked@example.com'); --",
    "' UNION SELECT * FROM users; --"
  ];

  describe('User Creation Endpoints', () => {
    it.each(maliciousInputs)('should prevent SQL injection in email: %s', async (maliciousEmail) => {
      const response = await request(app)
        .post('/api/users')
        .send({ 
          email: maliciousEmail,
          name: 'Test User',
          password: 'password123'
        });
      
      expect(response.status).toBe(400);
      
      // Vérifier que la table users existe toujours
      const users = await repository.find();
      expect(users).toBeDefined();
    });

    it.each(maliciousInputs)('should prevent SQL injection in name: %s', async (maliciousName) => {
      const response = await request(app)
        .post('/api/users')
        .send({ 
          email: 'test@example.com',
          name: maliciousName,
          password: 'password123'
        });
      
      expect(response.status).toBe(400);
      
      // Vérifier qu'aucun utilisateur malveillant n'a été créé
      const users = await repository.find({ where: { name: maliciousName } });
      expect(users.length).toBe(0);
    });
  });

  describe('User Query Endpoints', () => {
    it.each(maliciousInputs)('should prevent SQL injection in search: %s', async (maliciousSearch) => {
      const response = await request(app)
        .get(`/api/users/search?q=${encodeURIComponent(maliciousSearch)}`);
      
      expect(response.status).toBe(400);
    });

    it.each(maliciousInputs)('should prevent SQL injection in filter: %s', async (maliciousFilter) => {
      const response = await request(app)
        .get(`/api/users?filter=${encodeURIComponent(maliciousFilter)}`);
      
      expect(response.status).toBe(400);
    });
  });
});
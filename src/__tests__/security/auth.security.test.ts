import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../app.module';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../../models/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

describe('Authentication Security Tests', () => {
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

  describe('Password Security', () => {
    it('should hash passwords before storage', async () => {
      const userData = { 
        email: 'test@example.com',
        password: 'StrongP@ssw0rd123',
        name: 'Test User'
      };
      
      const response = await request(app)
        .post('/api/users')
        .send(userData);
      
      expect(response.status).toBe(201);
      
      const user = await repository.findOne({ 
        where: { email: userData.email }
      });
      
      expect(user.passwordHash).not.toBe(userData.password);
      expect(user.passwordHash).toMatch(/^\$2[aby]\$\d+\$/);
      expect(await bcrypt.compare(userData.password, user.passwordHash)).toBeTruthy();
    });

    it('should enforce password complexity requirements', async () => {
      const weakPasswords = [
        'short',             // Too short
        'nouppercasenum1',   // No uppercase
        'NOLOWERCASENUM1',   // No lowercase
        'NoSpecialChar1',    // No special char
        'NoNumber@letters',  // No number
        '12345678@A'        // Not complex enough
      ];

      for (const password of weakPasswords) {
        const response = await request(app)
          .post('/api/users')
          .send({
            email: 'test@example.com',
            password: password,
            name: 'Test User'
          });

        expect(response.status).toBe(400);
        expect(response.body.message).toMatch(/password/i);
      }
    });
  });

  describe('Login Security', () => {
    it('should prevent password enumeration', async () => {
      const existingUser = {
        email: 'existing@example.com',
        password: 'StrongP@ssw0rd123',
        name: 'Existing User'
      };

      // Créer un utilisateur
      await request(app)
        .post('/api/users')
        .send(existingUser);

      // Test avec email existant
      const response1 = await request(app)
        .post('/api/auth/login')
        .send({
          email: existingUser.email,
          password: 'WrongPassword123!'
        });

      // Test avec email inexistant
      const response2 = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'WrongPassword123!'
        });

      // Les réponses doivent être identiques
      expect(response1.status).toBe(response2.status);
      expect(response1.body.message).toBe(response2.body.message);
      expect(response1.body).not.toHaveProperty('error');
      expect(response2.body).not.toHaveProperty('error');
    });

    it('should implement rate limiting', async () => {
      const loginAttempts = 10;
      const loginData = {
        email: 'test@example.com',
        password: 'WrongPassword123!'
      };

      // Faire plusieurs tentatives de connexion
      for (let i = 0; i < loginAttempts; i++) {
        await request(app)
          .post('/api/auth/login')
          .send(loginData);
      }

      // La dernière tentative doit être bloquée
      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData);

      expect(response.status).toBe(429);
      expect(response.body.message).toMatch(/too many/i);
    });
  });

  describe('Session Security', () => {
    it('should generate secure JWT tokens', async () => {
      // Créer un utilisateur
      const userData = {
        email: 'test@example.com',
        password: 'StrongP@ssw0rd123',
        name: 'Test User'
      };

      await request(app)
        .post('/api/users')
        .send(userData);

      // Login pour obtenir le token
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: userData.email,
          password: userData.password
        });

      expect(response.status).toBe(200);
      expect(response.body.token).toBeDefined();
      expect(response.body.token).toMatch(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/);
    });

    it('should invalidate expired tokens', async () => {
      // Créer un utilisateur et obtenir un token
      const userData = {
        email: 'test@example.com',
        password: 'StrongP@ssw0rd123',
        name: 'Test User'
      };

      await request(app)
        .post('/api/users')
        .send(userData);

      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: userData.email,
          password: userData.password
        });

      const token = loginResponse.body.token;

      // Attendre que le token expire (simulé)
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Essayer d'accéder à une route protégée
      const response = await request(app)
        .get('/api/users/me')
        .set('Authorization', `Bearer ${token}`);

      expect(response.status).toBe(401);
    });
  });
});
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../app.module';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../models/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

describe('Security Tests', () => {
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

  it('should prevent SQL injection in user queries', async () => {
    const maliciousEmail = "'; DROP TABLE users; --";
    const response = await request(app)
      .post('/api/users')
      .send({ email: maliciousEmail, name: 'Test', password: 'pass123' });
    
    expect(response.status).toBe(400);
    // Vérifier que la table users existe toujours
    const users = await repository.find();
    expect(users).toBeDefined();
  });

  it('should hash passwords before storage', async () => {
    const userData = { email: 'test@example.com', password: 'plaintext123', name: 'Test User' };
    await request(app).post('/api/users').send(userData);
    
    const user = await repository.findOne({ where: { email: userData.email } });
    expect(user.passwordHash).not.toBe('plaintext123');
    expect(user.passwordHash).toMatch(/^\$2[aby]\$\d+\$/); // bcrypt format
  });

  it('should prevent password enumeration attacks', async () => {
    // Test avec email existant vs inexistant
    const existingEmail = 'existing@example.com';
    const nonExistingEmail = 'nonexisting@example.com';
    
    // Créer un utilisateur existant
    const user = new User();
    user.email = existingEmail;
    user.passwordHash = await bcrypt.hash('password123', 10);
    user.name = 'Existing User';
    await repository.save(user);
    
    const response1 = await request(app)
      .post('/api/auth/login')
      .send({ email: existingEmail, password: 'wrongpass' });
    
    const response2 = await request(app)
      .post('/api/auth/login')
      .send({ email: nonExistingEmail, password: 'wrongpass' });
    
    // Les deux doivent avoir la même réponse générique
    expect(response1.status).toBe(response2.status);
    expect(response1.body.message).toBe(response2.body.message);
  });
});
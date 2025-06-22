import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../app.module';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../../models/user.entity';
import { Repository } from 'typeorm';

describe('Input Validation Security Tests', () => {
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

  describe('Email Validation', () => {
    const invalidEmails = [
      'notanemail',           // Format invalide
      '@example.com',         // Pas de partie locale
      'user@',                // Pas de domaine
      'user@.com',            // Domaine invalide
      'user..user@test.com',  // Double point
      'user@test..com',       // Double point dans le domaine
      ' user@test.com ',      // Espaces
      'user@-test.com',       // Tiret au début du domaine
      'user@test-.com',       // Tiret à la fin du domaine
      'a'.repeat(65) + '@example.com', // Trop long
      'user@' + 'a'.repeat(255) + '.com', // Domaine trop long
      'user+test@example.com' // Caractères spéciaux
    ];

    it.each(invalidEmails)('should reject invalid email: %s', async (email) => {
      const response = await request(app)
        .post('/api/users')
        .send({
          email,
          password: 'StrongP@ssw0rd123',
          name: 'Test User'
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toMatch(/email/i);
    });

    it('should handle email case sensitivity correctly', async () => {
      // Créer un utilisateur
      await request(app)
        .post('/api/users')
        .send({
          email: 'test@example.com',
          password: 'StrongP@ssw0rd123',
          name: 'Test User'
        });

      // Essayer de créer un utilisateur avec le même email en majuscules
      const response = await request(app)
        .post('/api/users')
        .send({
          email: 'TEST@EXAMPLE.COM',
          password: 'StrongP@ssw0rd123',
          name: 'Test User 2'
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toMatch(/email.*exists/i);
    });
  });

  describe('Name Validation', () => {
    const invalidNames = [
      '',                     // Vide
      ' ',                    // Espaces uniquement
      'a',                    // Trop court
      'a'.repeat(101),       // Trop long
      '<script>alert(1)</script>', // XSS
      '../../etc/passwd',    // Path traversal
      'Robert"); DROP TABLE users; --', // SQL Injection
      'Name\n\rWith\tControl\x00Characters' // Caractères de contrôle
    ];

    it.each(invalidNames)('should reject invalid name: %s', async (name) => {
      const response = await request(app)
        .post('/api/users')
        .send({
          email: 'test@example.com',
          password: 'StrongP@ssw0rd123',
          name
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toMatch(/name/i);
    });

    it('should handle Unicode names correctly', async () => {
      const validNames = [
        'José María',         // Espagnol
        '李小龙',             // Chinois
        'Σωκράτης',          // Grec
        'Иван Петров',       // Russe
        'محمد',              // Arabe
        'Sarah O\'Connor',    // Apostrophe
        'Jean-Pierre',       // Tiret
        'María del Pilar'    // Espace
      ];

      for (const name of validNames) {
        const response = await request(app)
          .post('/api/users')
          .send({
            email: `${name.toLowerCase().replace(/[^a-z]/g, '')}@example.com`,
            password: 'StrongP@ssw0rd123',
            name
          });

        expect(response.status).toBe(201);
        expect(response.body.data.name).toBe(name);
      }
    });
  });

  describe('Input Sanitization', () => {
    const maliciousInputs = [
      '<script>alert("xss")</script>',
      '"><script>alert("xss")</script>',
      'javascript:alert("xss")',
      'data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=',
      'onerror=alert("xss")',
      '<img src=x onerror=alert("xss")>',
      '<svg/onload=alert("xss")>',
      '<iframe src="javascript:alert(\'xss\')">',
      '/*-->*/</script>"><script>/*<!--*/alert("xss");</script>',
      'expressio\u006E(alert("xss"))'
    ];

    it.each(maliciousInputs)('should sanitize malicious input in name: %s', async (input) => {
      const response = await request(app)
        .post('/api/users')
        .send({
          email: 'test@example.com',
          password: 'StrongP@ssw0rd123',
          name: input
        });

      if (response.status === 201) {
        // Si l'input est accepté, vérifier qu'il a été assaini
        expect(response.body.data.name).not.toMatch(/<script>|javascript:|data:|onerror=|onload=/i);
      } else {
        // Sinon, vérifier que c'est rejeté proprement
        expect(response.status).toBe(400);
        expect(response.body.message).toMatch(/invalid|malicious|forbidden/i);
      }
    });

    it('should prevent HTML injection in responses', async () => {
      const user = await repository.save({
        email: 'test@example.com',
        passwordHash: 'hash',
        name: '<p>Test</p><script>alert("xss")</script>'
      });

      const response = await request(app)
        .get(`/api/users/${user.id}`);

      expect(response.status).toBe(200);
      expect(response.body.data.name).not.toMatch(/<script>/);
      expect(response.body.data.name).toBe('Test');
    });
  });
});
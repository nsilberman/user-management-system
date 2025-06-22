import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../app.module';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../models/user.entity';
import { Role } from '../models/role.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

describe('Authorization Tests', () => {
  let app: INestApplication;
  let userRepository: Repository<User>;
  let roleRepository: Repository<Role>;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    userRepository = moduleFixture.get<Repository<User>>(getRepositoryToken(User));
    roleRepository = moduleFixture.get<Repository<Role>>(getRepositoryToken(Role));
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(async () => {
    await userRepository.clear();
    await roleRepository.clear();
  });

  const createTestUser = async (email: string, roleName: string) => {
    const role = new Role();
    role.name = roleName;
    const savedRole = await roleRepository.save(role);

    const user = new User();
    user.email = email;
    user.passwordHash = await bcrypt.hash('password123', 10);
    user.name = `${roleName} User`;
    user.role = savedRole;
    const savedUser = await userRepository.save(user);

    // Générer un token JWT pour le test
    const response = await request(app)
      .post('/api/auth/login')
      .send({ email, password: 'password123' });

    return {
      ...savedUser,
      token: response.body.token
    };
  };

  it('should prevent unauthorized user modification', async () => {
    const user1 = await createTestUser('user1@example.com', 'user');
    const user2 = await createTestUser('user2@example.com', 'user');
    
    const response = await request(app)
      .put(`/api/users/${user2.id}`)
      .set('Authorization', `Bearer ${user1.token}`)
      .send({ name: 'Hacked Name' });
    
    expect(response.status).toBe(403);
    
    // Vérifier que le nom n'a pas été modifié
    const unchangedUser = await userRepository.findOne({ where: { id: user2.id } });
    expect(unchangedUser.name).toBe('user User');
  });

  it('should allow admin to modify any user', async () => {
    const admin = await createTestUser('admin@example.com', 'admin');
    const user = await createTestUser('user@example.com', 'user');
    
    const response = await request(app)
      .put(`/api/users/${user.id}`)
      .set('Authorization', `Bearer ${admin.token}`)
      .send({ name: 'Updated by Admin' });
    
    expect(response.status).toBe(200);
    
    // Vérifier que le nom a été modifié
    const updatedUser = await userRepository.findOne({ where: { id: user.id } });
    expect(updatedUser.name).toBe('Updated by Admin');
  });
});
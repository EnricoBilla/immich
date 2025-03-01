import { UserEntity } from '@app/database/entities/user.entity';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { newUserRepositoryMock } from '../../../test/test-utils';
import { AuthUserDto } from '../../decorators/auth-user.decorator';
import { IUserRepository } from './user-repository';
import { UserService } from './user.service';

describe('UserService', () => {
  let sui: UserService;
  let userRepositoryMock: jest.Mocked<IUserRepository>;

  const adminAuthUser: AuthUserDto = Object.freeze({
    id: 'admin_id',
    email: 'admin@test.com',
  });

  const immichAuthUser: AuthUserDto = Object.freeze({
    id: 'immich_id',
    email: 'immich@test.com',
  });

  const adminUser: UserEntity = {
    id: 'admin_id',
    email: 'admin@test.com',
    password: 'admin_password',
    salt: 'admin_salt',
    firstName: 'admin_first_name',
    lastName: 'admin_last_name',
    isAdmin: true,
    oauthId: '',
    shouldChangePassword: false,
    profileImagePath: '',
    createdAt: '2021-01-01',
    tags: [],
  };

  const immichUser: UserEntity = {
    id: 'immich_id',
    email: 'immich@test.com',
    password: 'immich_password',
    salt: 'immich_salt',
    firstName: 'immich_first_name',
    lastName: 'immich_last_name',
    isAdmin: false,
    oauthId: '',
    shouldChangePassword: false,
    profileImagePath: '',
    createdAt: '2021-01-01',
    tags: [],
  };

  const updatedImmichUser: UserEntity = {
    id: 'immich_id',
    email: 'immich@test.com',
    password: 'immich_password',
    salt: 'immich_salt',
    firstName: 'updated_immich_first_name',
    lastName: 'updated_immich_last_name',
    isAdmin: false,
    oauthId: '',
    shouldChangePassword: true,
    profileImagePath: '',
    createdAt: '2021-01-01',
    tags: [],
  };

  beforeAll(() => {
    userRepositoryMock = newUserRepositoryMock();

    sui = new UserService(userRepositoryMock);
  });

  it('should be defined', () => {
    expect(sui).toBeDefined();
  });

  describe('Update user', () => {
    it('should update user', async () => {
      const requestor = immichAuthUser;
      const userToUpdate = immichUser;

      userRepositoryMock.get.mockImplementationOnce(() => Promise.resolve(immichUser));
      userRepositoryMock.get.mockImplementationOnce(() => Promise.resolve(userToUpdate));
      userRepositoryMock.update.mockImplementationOnce(() => Promise.resolve(updatedImmichUser));

      const result = await sui.updateUser(requestor, {
        id: userToUpdate.id,
        shouldChangePassword: true,
      });
      expect(result.shouldChangePassword).toEqual(true);
    });

    it('user can only update its information', () => {
      const requestor = immichAuthUser;

      userRepositoryMock.get.mockImplementationOnce(() => Promise.resolve(immichUser));

      const result = sui.updateUser(requestor, {
        id: 'not_immich_auth_user_id',
        password: 'I take over your account now',
      });
      expect(result).rejects.toBeInstanceOf(BadRequestException);
    });

    it('admin can update any user information', async () => {
      const requestor = adminAuthUser;
      const userToUpdate = immichUser;

      userRepositoryMock.get.mockImplementationOnce(() => Promise.resolve(adminUser));
      userRepositoryMock.get.mockImplementationOnce(() => Promise.resolve(userToUpdate));
      userRepositoryMock.update.mockImplementationOnce(() => Promise.resolve(updatedImmichUser));

      const result = await sui.updateUser(requestor, {
        id: userToUpdate.id,
        shouldChangePassword: true,
      });

      expect(result).toBeDefined();
      expect(result.id).toEqual(updatedImmichUser.id);
      expect(result.shouldChangePassword).toEqual(updatedImmichUser.shouldChangePassword);
    });

    it('update user information should throw error if user not found', () => {
      const requestor = adminAuthUser;
      const userToUpdate = immichUser;

      userRepositoryMock.get.mockImplementationOnce(() => Promise.resolve(adminUser));
      userRepositoryMock.get.mockImplementationOnce(() => Promise.resolve(null));

      const result = sui.updateUser(requestor, {
        id: userToUpdate.id,
        shouldChangePassword: true,
      });
      expect(result).rejects.toBeInstanceOf(NotFoundException);
    });

    it('cannot delete admin user', () => {
      const requestor = adminAuthUser;

      userRepositoryMock.get.mockImplementationOnce(() => Promise.resolve(adminUser));
      userRepositoryMock.get.mockImplementationOnce(() => Promise.resolve(adminUser));

      const result = sui.deleteUser(requestor, adminAuthUser.id);

      expect(result).rejects.toBeInstanceOf(BadRequestException);
    });
  });
});

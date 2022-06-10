import { OnGatewayConnection, OnGatewayDisconnect, WebSocketGateway, WebSocketServer } from '@nestjs/websockets';
import { Socket, Server } from 'socket.io';
import { ImmichJwtService } from '../../modules/immich-auth/immich-jwt.service';
import {Logger, UseGuards} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from '../user/entities/user.entity';
import { Repository } from 'typeorm';
import {ImmichAuthGuard} from "../../modules/immich-auth/guards/immich-auth.guard";

@WebSocketGateway()
export class CommunicationGateway implements OnGatewayConnection, OnGatewayDisconnect {
  constructor(
    private immichJwtService: ImmichJwtService,

    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,

    private authGuard: ImmichAuthGuard,
  ) {}

  @WebSocketServer() server: Server;

  handleDisconnect(client: Socket) {
    client.leave(client.nsp.name);

    Logger.log(`Client ${client.id} disconnected`);
  }

  async handleConnection(client: Socket, ...args: any[]) {
    // todo handle websocket connection with oauth2
    Logger.log(`New websocket connection: ${client.id}`, 'NewWebSocketConnection');
    const accessToken = client.handshake.headers.authorization.split(' ')[1];
    const res = await this.immichJwtService.validateToken(accessToken);

    // todo handle websocket connection with oauth2

    if (!res.status) {
      client.emit('error', 'unauthorized');
      client.disconnect();
      return;
    }

    const user = await this.userRepository.findOne({ where: { id: res.userId } });
    if (!user) {
      client.emit('error', 'unauthorized');
      client.disconnect();
      return;
    }

    client.join(user.id);
  }
}

import { Controller, Get, Post, Body, Patch, Param, Delete, ValidationPipe } from '@nestjs/common';
import { TagService } from './tag.service';
import { CreateTagDto } from './dto/create-tag.dto';
import { UpdateTagDto } from './dto/update-tag.dto';
import { Authenticated } from '../../decorators/authenticated.decorator';
import { ApiTags } from '@nestjs/swagger';
import { AuthUserDto, GetAuthUser } from '../../decorators/auth-user.decorator';
import { mapTag, TagResponseDto } from "./response-dto/tag-response.dto";

@Authenticated()
@ApiTags('Tag')
@Controller('tag')
export class TagController {
  constructor(private readonly tagService: TagService) {}

  @Post()
  create(@GetAuthUser() authUser: AuthUserDto, @Body(ValidationPipe) createTagDto: CreateTagDto): Promise<TagResponseDto> {
    return this.tagService.create(authUser, createTagDto);
  }

  @Get()
  findAll(@GetAuthUser() authUser: AuthUserDto): Promise<TagResponseDto[]> {
    return this.tagService.findAll(authUser);
  }

  @Get(':id')
  async findOne(@GetAuthUser() authUser: AuthUserDto, @Param('id') id: string): Promise<TagResponseDto> {
    const tag = await this.tagService.findOne(authUser, id);
    return mapTag(tag);
  }

  @Patch(':id')
  update(
    @GetAuthUser() authUser: AuthUserDto,
    @Param('id') id: string,
    @Body(ValidationPipe) updateTagDto: UpdateTagDto,
  ): Promise<TagResponseDto>  {
    return this.tagService.update(authUser, id, updateTagDto);
  }

  @Delete(':id')
  delete(@GetAuthUser() authUser: AuthUserDto, @Param('id') id: string): Promise<void> {
    return this.tagService.remove(authUser, id);
  }
}

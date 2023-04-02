/* eslint-disable prettier/prettier */
import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';


@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) {}
    
    async signup(dto:AuthDto){
        try{
            // generate the password hash
            const hash =  await argon.hash(dto.password);
            // save the user
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    password: hash,
                },
            });
            delete user.password;
            // return the user
    
            return user;
        }
        catch(err){
            if(err instanceof PrismaClientKnownRequestError){
                if(err.code === 'P2002'){
                    throw new ForbiddenException('Credentials Taken');
                }
            }throw err;
        }
    }
   
    async signin(dto:AuthDto){
        // find the user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });

        // if the user does not exist throw an error
        if(!user){
            throw new ForbiddenException('Invalid Credentials');
        }
        // compare the password with the hash
        const valid = await argon.verify(user.password, dto.password);
        // if the password is not correct throw an error
        if(!valid){
            throw new ForbiddenException('Invalid Credentials');
        }
        // return the user
        delete user.password;
        return user;
    }   
}

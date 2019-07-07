import axios, { AxiosResponse } from 'axios';
import { prisma, User } from '../generated/prisma-client';
import bcrypt from 'bcrypt';

async function main(): Promise<void> {
  const users: any[] = await fetchRandomUsers();
  users.forEach(
    async (user: any, index: number): Promise<void> => {
      const passwordHash: string = await bcrypt.hash(user.login.password, 10);
      const newUser: User = await prisma.createUser({
        name: user.name.first,
        passwordHash,
        admin: index === 0,
        todos: {
          create: [
            {
              text: 'Did a thing',
              complete: true
            },
            {
              text: 'Do a thing',
              complete: false
            }
          ]
        }
      });
      console.log(`Created new user: ${newUser.name} (ID: ${newUser.id})`);
    }
  );
}

async function fetchRandomUsers(): Promise<any[]> {
  const url = 'https://randomuser.me/api/?results=5&nat=US&seed=balls';
  const response: AxiosResponse = await axios.get(url);
  return response.data.results;
}

main().catch((err: Error): void => console.error(err));

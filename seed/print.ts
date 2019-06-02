import { prisma, User, Todo } from '../generated/prisma-client';

async function main(): Promise<void> {
  const users: User[] = await prisma.users();
  const todos: Todo[] = await prisma.todoes();

  console.log('Users:', JSON.stringify(users, null, 2));
  console.log('Todos:', JSON.stringify(todos, null, 2));
}

main().catch((err: Error): void => console.error(err));

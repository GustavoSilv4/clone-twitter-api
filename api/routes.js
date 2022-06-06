import Router from 'koa-router';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import { omit } from 'ramda';
import jwt from 'jsonwebtoken';

export const router = new Router();

const prisma = new PrismaClient();

router.get('/tweets', async ctx => {
    const [, token] = ctx.request.headers?.authorization?.split(' ') || [];

    if (!token) {
        ctx.status = 401
        return
    }

    try {
        jwt.verify(token, process.env.JWT_SECRET)
        const tweets = await prisma.tweet.findMany({
            include: {
                user: true
            }
        });
        ctx.body = tweets;

    } catch (error) {
        ctx.status = 401
        return
    }

})

router.post('/tweets', async ctx => {
    const [, token] = ctx.request.headers?.authorization?.split(' ') || []

    if (!token) {
        ctx.status = 401
        return
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET)
        const tweets = await prisma.tweet.create({
            data: {
                userId: payload.sub,
                text: ctx.request.body.text
            },
        })

        ctx.body = tweets
    } catch (error) {
        console.log(error)
        ctx.status = 401
        return
    }
})

router.delete('/tweets', async ctx => {
    const id = 'cl40m9prd0011os0r5k4vfm46'

    const doc = await prisma.tweet.delete({
        where: { id: id }
    })
    ctx.body = doc
})

router.post('/signup', async ctx => {
    const saltRounds = 10
    const passwordHash = bcrypt.hashSync(ctx.request.body.password, saltRounds);
    try {
        const { ...user } = await prisma.user.create({  // 
            data: {
                name: ctx.request.body.name,
                username: ctx.request.body.username,
                email: ctx.request.body.email,
                password: passwordHash,
            }
        })

        const accessToken = jwt.sign({
            sub: user.id
        }, process.env.JWT_SECRET, { expiresIn: '24h' })

        ctx.body = omit(['password'], { ...user, accessToken }) // no retorno eu descontruo o user e retiro o password com o omit
    } catch (error) {
        if (error.meta && !error.meta.target) {
            ctx.status = 422;
            ctx.body = 'Email ou Username já cadastrado';
            return
        }
        ctx.status = 500;
        ctx.body = 'Interal error';
    }

})

router.get('/login', async ctx => {
    const [, token] = ctx.request.headers.authorization.split(' ') // Antes do split: base tokenBase64, depois: tokenBase64
    const [email, plainTextpassword] = Buffer.from(token, 'base64').toString().split(':') // O proprio node através do buffer converte de base64 para string gerando: email:senha que depoise do split: [email, senha]

    const user = await prisma.user.findUnique({
        where: {
            email: email,
        }
    })

    if (!user) {  // Se não houver user com o email passado retorna o error
        ctx.status = 404
        ctx.body = 'Dados não cadastrado'
        return
    }

    // Se achou o user como o email passado ele irar continuar para verificao a baixo

    const passwordMatch = await bcrypt.compare(plainTextpassword, user.password);  // Compara as senhas criptografadas

    if (passwordMatch) {
        const accessToken = jwt.sign({
            sub: user.id
        }, process.env.JWT_SECRET, { expiresIn: '24h' })

        ctx.body = omit(['password'], { ...user, accessToken })
        return
    }

    ctx.status = 404;

})


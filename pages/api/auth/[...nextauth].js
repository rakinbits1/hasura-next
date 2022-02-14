import NextAuth from "next-auth"
import Providers from 'next-auth/providers'
import jwt from "jsonwebtoken";
const token = "LiMN3XtAdGvD6yQDdEd9wrmP";
export default NextAuth({
  providers: [
    Providers.Credentials({
      name: "Credentials",
      id:"Credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: {  label: "Password", type: "password" }
      },
      async authorize(credentials, req) {
        const gqlResponses =  await fetch(`https://skilled-gelding-55.hasura.app/v1/graphql`,{
          headers: {
            "X-Hasura-Admin-Secret": 'iCKvERK1ph8qoT4nZivnXCdebNbHav8rnZn1khynIpfer5l1iE1sr1SJfyf4gqx0',
            "Content-Type": "application/json",
          },
          method:"POST",
          body: JSON.stringify({
            query: `
            query FindUserByEmail($email: String!) {
              users(where: { email: { _eq: $email} }) {
                id
                email
                name
              }
            }
            `,
            variables: {
              email: credentials.email
            },
        })
      })

      const gqlResponse = await gqlResponses.json()
      const user = gqlResponse?.data?.users
        if (user) {
          return {
           id:user[0]?.id,
           email:user[0]?.email,
           name:user[0]?.name
          };
        }
        return null;
      }
    })
  ],
  secret: process.env.SECRET,

  session: {
    jwt: true,
  },
  jwt: {
    secret: process.env.SECRET,
    encode: async ({ secret, token, maxAge }) => {
      console.log(secret,token,'encode')
      const jwtClaims = {
        "sub": token.sub?.toString() ,
        "name": token.name ,
        "email": token.email,
        "iat": Date.now() / 1000,
        "exp": Math.floor(Date.now() / 1000) + (24*60*60),
        "https://hasura.io/jwt/claims": {
          "x-hasura-allowed-roles": ["admin"],
          "x-hasura-default-role": "admin",
          "x-hasura-role": "admin",
          "x-hasura-user-id": token.id,
        }
      };
      const encodedToken = jwt.sign(jwtClaims, secret, { algorithm: 'HS256'});
      console.log(encodedToken,'encodedToken')
      return encodedToken;
    },
    decode: async ({ secret, token, maxAge }) => {
      console.log(secret,token,'decode')
      const decodedToken = jwt.verify(token, secret, { algorithms: ['HS256']});
      return decodedToken;
    },
  },

  pages: {
    // signIn: '/api/auth/signin',  // Displays signin buttons
    // signOut: '/api/auth/signout', // Displays form with sign out button
    // error: '/api/auth/error', // Error code passed in query string as ?error=
    // verifyRequest: '/api/auth/verify-request', // Used for check email page
    // newUser: null // If set, new users will be directed here on first sign in
  },

  callbacks: {
    // async signIn(user, account, profile) { return true },
    // async redirect(url, baseUrl) { return baseUrl },
    async session(session, token) { 
      console.log(session,token,'session')
      const encodedToken = jwt.sign(token, process.env.SECRET, { algorithm: 'HS256'});
      session.id = token.id;
      session.token = encodedToken;
      return Promise.resolve(session);
    },
    async jwt(token, user, account, profile, isNewUser) { 
      const isUserSignedIn = user ? true : false;
      // make a http call to our graphql api
      // store this in postgres
      if(isUserSignedIn) {
        token.id = user.id?.toString();
      }
      return Promise.resolve(token);
    }
  },

  // Events are useful for logging
  // https://next-auth.js.org/configuration/events
  events: {},

  // Enable debug messages in the console if you are having problems
  debug: true,
})

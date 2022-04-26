import axios from "axios";
import Image from "next/image";
import imageLoader from "../../imageLoader";
import { Character, GetCharacterResults } from "../../types/types";
import Head from "next/head";
import Link from "next/link";
import { GetServerSideProps } from "next";
import Layout from "../../layouts/Layout";

function CharacterPage({ character }: { character: Character }) {
  return (
    <div>
      <Head>
        <title>character</title>
      </Head>
      {CharacterPage.name}
      <Image
        src={character.image}
        alt={character.name}
        width={300}
        height={300}
        loader={imageLoader}
        unoptimized
      />
      <Link href="/">home</Link>
    </div>
  );
}

CharacterPage.getLayout = (page: typeof CharacterPage) => {
  return <Layout>{page}</Layout>;
};

export default CharacterPage;

// export const getStaticPaths = async () => {
//   const { data }: { data: GetCharacterResults } = await axios.get(
//     "https://rickandmortyapi.com/api/character"
//   );

//   const { results } = data;

//   return {
//     fallback: false,
//     paths: results.map((character) => {
//       return {
//         params: { id: String(character.id) },
//       };
//     }),
//   };
// };

export const getServerSideProps: GetServerSideProps = async (context) => {
  const { data } = await axios.get(
    "https://rickandmortyapi.com/api/character/" + context.query.id
  );

  return {
    props: {
      character: data,
    },
  };
};

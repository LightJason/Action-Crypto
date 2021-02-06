/*
 * @cond LICENSE
 * ######################################################################################
 * # LGPL License                                                                       #
 * #                                                                                    #
 * # This file is part of the LightJason                                                #
 * # Copyright (c) 2015-19, LightJason (info@lightjason.org)                            #
 * # This program is free software: you can redistribute it and/or modify               #
 * # it under the terms of the GNU Lesser General Public License as                     #
 * # published by the Free Software Foundation, either version 3 of the                 #
 * # License, or (at your option) any later version.                                    #
 * #                                                                                    #
 * # This program is distributed in the hope that it will be useful,                    #
 * # but WITHOUT ANY WARRANTY; without even the implied warranty of                     #
 * # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                      #
 * # GNU Lesser General Public License for more details.                                #
 * #                                                                                    #
 * # You should have received a copy of the GNU Lesser General Public License           #
 * # along with this program. If not, see http://www.gnu.org/licenses/                  #
 * ######################################################################################
 * @endcond
 */

package org.lightjason.agentspeak.action.crypto;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.lightjason.agentspeak.error.context.CExecutionException;
import org.lightjason.agentspeak.error.context.CExecutionIllegalStateException;
import org.lightjason.agentspeak.error.context.CExecutionIllegealArgumentException;
import org.lightjason.agentspeak.language.CRawTerm;
import org.lightjason.agentspeak.language.ITerm;
import org.lightjason.agentspeak.language.execution.IContext;
import org.lightjason.agentspeak.testing.IBaseTest;

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;


/**
 * test action crypto
 */
public final class TestCActionCrypto extends IBaseTest
{

    /**
     * data provider generator of hash definition
     *
     * @return data
     */
    public static Stream<Arguments> generatehash()
    {
        return Stream.of(
            Arguments.of( "adler-32", new String[]{"7804c01a", "911c63b0"} ),
            Arguments.of( "crc-32", new String[]{"45154713", "29369833"} ),
            Arguments.of( "crc-32c", new String[]{"387e0716", "4411bf68"} ),
            Arguments.of( "murmur3-32", new String[]{"306202a8", "08b9852d"} ),
            Arguments.of( "murmur3-128", new String[]{"636cc4ff5f7ed59b51f29d6d949b4709", "f4459439308d1248efc0532fb4cd6d79"} ),
            Arguments.of( "siphash-2-4", new String[]{"4f27c08e5981bc5a", "82ee572bf0a0dde4"} )
        );
    }

    /**
     * data provider generator of crypt key definition
     *
     * @return data
     */
    public static Stream<Arguments> generatecrypt()
    {
        return Stream.of(
            Arguments.of( "des", 1, 0 ),
            Arguments.of( "aes", 1, 0 ),
            Arguments.of( "rsa", 2, 1 )
        );
    }

    /**
     * test crypt key generation
     *
     * @param p_input input definition
     * @param p_result result
     * @param p_ignore testing value
     */
    @ParameterizedTest
    @MethodSource( "generatecrypt" )
    public void createkey( final String p_input, final Integer p_result, final Integer p_ignore )
    {
        final List<ITerm> l_return = new ArrayList<>();

        new CCreateKey().execute(
            false, IContext.EMPTYPLAN,
            Stream.of( CRawTerm.of( p_input ) ).collect( Collectors.toList() ),
            l_return
        );

        Assertions.assertEquals( p_result.intValue(), l_return.size() );
    }


    /**
     * test wrong algorithm
     */
    @Test
    public void wrongalgorithm() throws NoSuchAlgorithmException
    {
        final Key l_key = KeyGenerator.getInstance( "HmacSHA1" ).generateKey();

        Assertions.assertThrows( CExecutionIllegealArgumentException.class,
                                 () -> new CEncrypt().execute(
                                     false,
                                     IContext.EMPTYPLAN,
                                     Stream.of( l_key ).map( CRawTerm::of ).collect( Collectors.toList() ),
                                     Collections.emptyList()
                                 )
        );

        Assertions.assertThrows( CExecutionIllegealArgumentException.class,
                                 () -> new CDecrypt().execute(
                                     false,
                                     IContext.EMPTYPLAN,
                                    Stream.of( l_key ).map( CRawTerm::of ).collect( Collectors.toList() ),
                                    Collections.emptyList()
                            )
        );
    }

    /**
     * test decrypt execute array
     */
    @Test
    public void decryptexecutionerror() throws NoSuchAlgorithmException
    {
        final Pair<Key, Key> l_key = ECryptAlgorithm.RSA.generateKey();
        final List<ITerm> l_return = new ArrayList<>();

        new CEncrypt().execute(
            false,
            IContext.EMPTYPLAN,
            Stream.of( l_key.getLeft(), "xxx" ).map( CRawTerm::of ).collect( Collectors.toList() ),
            l_return
        );

        Assertions.assertEquals( 1, l_return.size() );

        Assertions.assertThrows( CExecutionIllegalStateException.class,
                                 () -> new CDecrypt().execute(
                                    false,
                                    IContext.EMPTYPLAN,
                                    Stream.of( l_key.getLeft(), l_return.get( 0 ).<String>raw() ).map( CRawTerm::of ).collect( Collectors.toList() ),
                                    l_return
                                )
        );
    }

    /**
     * test hashing
     *
     * @param p_input input data
     * @param p_return result
     */
    @ParameterizedTest
    @MethodSource( "generatehash" )
    public void hash( final String p_input, final String[] p_return )
    {
        final List<ITerm> l_return = new ArrayList<>();

        Assertions.assertTrue(
            execute(
                new CHash(),
                false,
                Stream.of( CRawTerm.of( p_input ), CRawTerm.of( "test string" ), CRawTerm.of( 1234 ) ).collect( Collectors.toList() ),
                l_return
            )
        );

        Assertions.assertArrayEquals( p_return, l_return.stream().map( ITerm::<String>raw ).toArray( String[]::new ) );
    }

    /**
     * test hash exception
     */
    @Test
    public void hashexception()
    {
        Assertions.assertThrows( CExecutionException.class,
                                 () -> new CHash().execute(
                                     false, IContext.EMPTYPLAN,
                                     Stream.of( CRawTerm.of( "xxx" ), CRawTerm.of( 1234 ) ).collect( Collectors.toList() ),
                                     Collections.emptyList()
                                 )
        );
    }



    /**
     * test key generation on error call
     */
    @Test
    public void createkeyError()
    {
        Assertions.assertThrows( CExecutionIllegealArgumentException.class,
                                 () -> new CCreateKey().execute(
                                false,
                                    IContext.EMPTYPLAN,
                                    Stream.of( CRawTerm.of( "test" ) ).collect( Collectors.toList() ),
                                    Collections.emptyList()
                                )
        );
    }

    /**
     * test encrypting and decrypting
     *
     * @param p_input input data
     * @param p_result result data
     * @param p_index index position
     */
    @ParameterizedTest
    @MethodSource( "generatecrypt" )
    public void encryptdecreypt( final String p_input, final Integer p_result, final Integer p_index )
    {
        final List<ITerm> l_returnkey = new ArrayList<>();

        new CCreateKey().execute(
            false, IContext.EMPTYPLAN,
            Stream.of( CRawTerm.of( p_input ) ).collect( Collectors.toList() ),
            l_returnkey
        );

        Assertions.assertEquals( p_result.intValue(), l_returnkey.size() );


        final List<ITerm> l_returnencrypt = new ArrayList<>();

        new CEncrypt().execute(
            false, IContext.EMPTYPLAN,
            Stream.of( l_returnkey.get( 0 ), CRawTerm.of( "test string" ), CRawTerm.of( 12345 ) ).collect( Collectors.toList() ),
            l_returnencrypt
        );


        final List<ITerm> l_return = new ArrayList<>();

        new CDecrypt().execute(
            false, IContext.EMPTYPLAN,
            Stream.concat( Stream.of( l_returnkey.get( p_index ) ), l_returnencrypt.stream() ).collect( Collectors.toList() ),
            l_return
        );


        Assertions.assertEquals( 2, l_return.size() );
        Assertions.assertEquals( "test string", l_return.get( 0 ).raw() );
        Assertions.assertEquals( 12345, l_return.get( 1 ).<Number>raw() );
    }

}

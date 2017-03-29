<?php

/*
 * Copyright (c) 2014-2017 Christophe Painchaud <shellescape _AT_ gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

class CsvParser
{
    /**
     * @param string $fileName
     * @param string $errorMessage
     * @param bool $hasHeaders
     * @param bool $skipEmptyLines
     * @param null|string[] $customHeaders
     * @return false|string[]
     */
    static public function &parseFile( $fileName, &$errorMessage, $hasHeaders = true, $skipEmptyLines = false,$customHeaders = null)
    {
        $ret = false;

        if( !file_exists($fileName) )
        {
            $errorMessage = "file '$fileName' doesn't exists";
            return $ret;
        }

        $content = file_get_contents($fileName);

        if( $content === FALSE )
        {
            $errorMessage = "file '$fileName' could not be open (permission problem?)";
            return $ret;
        }

        $ret = CsvParser::parseString($content, $errorMessage, $hasHeaders, $skipEmptyLines, $customHeaders);

        return $ret;
    }

    /**
     * @param string $content
     * @param string $errorMessage
     * @param bool $hasHeaders
     * @param bool $skipEmptyLines
     * @param null|string[] $customHeaders
     * @return false|string[]
     */
    static public function &parseString( $content, &$errorMessage, $hasHeaders = true, $skipEmptyLines = false, $customHeaders = null)
    {
        $ret = false;

        $content = explode("\n", $content);

        if( $hasHeaders )
        {
            if( $customHeaders === null )
            {
                // first line is headers, let's get it.
                if( count($content) < 1 )
                {
                    $errorMessage = 'file is empty, no header to parse';
                    return $ret;
                }

                $headerLine = trim($content[0]);
                unset($content[0]);

                if( strlen($headerLine) < 1 )
                {
                    $errorMessage = 'header is empty line';
                    return $ret;
                }

                $headers = explode(',', $headerLine);
                if( count($headers) < 1 )
                {
                    $errorMessage = 'file is empty or header malformed';
                    return $ret;
                }

                $uniqueCheck = Array();

                foreach( $headers as &$h )
                {
                    if( strlen($h) < 1 )
                    {
                        $errorMessage = 'one of the header column name is empty';
                        return $ret;
                    }
                    if( isset($uniqueCheck[$h]) )
                    {
                        $errorMessage = "two or more headers columns have same name '$h'";
                        return $ret;
                    }

                    $uniqueCheck[$h] = true;
                }

            }
            else
            {
                if( !is_array($customHeaders) )
                {
                    $errorMessage = "two or more headers columns have same name";
                    return $ret;
                }

                $headers = Array();

                foreach( $customHeaders as &$h )
                {
                    if( strlen($h) < 1 )
                    {
                        $errorMessage = 'one of the header column name is empty';
                        return $ret;
                    }

                    $headers[] = $h;
                }
            }

            $response = Array( 'header' => &$headers );
        }

        $records = Array();
        $response['records'] = &$records;

        $countLines = -1;
        foreach($content as &$line)
        {
            $countLines++;
            $line = trim($line);
            if( isset($csvRecord) )
                unset($csvRecord);

            $csvRecord = Array();
            $records[] = &$csvRecord;

            if( strlen($line) < 1 )
            {
                if( $skipEmptyLines == true )
                    continue;

                $errorMessage = "line #{$countLines} is empty";
                return $ret;
            }

            $explodedLine = str_getcsv($line);


            for($i=0; $i < count($explodedLine); $i++)
            {
                if( isset($headers[$i]) )
                {
                    $csvRecord[$headers[$i]] = $explodedLine[$i];
                }
                else
                {
                    $csvRecord['col#'.$i] = $explodedLine[$i];
                }
            }

        }

        $response['count'] = $countLines+1;

        return $records;
    }
} 
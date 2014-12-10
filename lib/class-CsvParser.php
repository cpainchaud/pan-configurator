<?php
/**
 * Created by PhpStorm.
 * User: cpainchaud
 * Date: 17/11/2014
 * Time: 07:18
 */

class CsvParser
{
    /**
     * @param string $fileName
     * @param string $errorMessage
     * @param bool $hasHeaders
     * @param null|string[] $customHeaders
     * @return false|Array
     */
    static public function & parseFile( $fileName, &$errorMessage, $hasHeaders = true, $customHeaders = null)
    {
        if( !file_exists($fileName) )
        {
            $errorMessage = "file '$fileName' doesn't exists";
            return false;
        }

        $content = file_get_contents($fileName);

        if( $content === FALSE )
        {
            $errorMessage = "file '$fileName' could not be open (permission problem?)";
            return false;
        }

        $content = explode("\n", $content);

        if( $hasHeaders )
        {
            if( $customHeaders === null )
            {
                // first line is headers, let's get it.
                if( count($content) < 1 )
                {
                    $errorMessage = 'file is empty, no header to parse';
                    return false;
                }

                $headerLine = $content[0];
                unset($content[0]);

                if( strlen($headerLine) < 1 )
                {
                    $errorMessage = 'header is empty line';
                    return false;
                }

                $headers = explode(',', $headerLine);
                if( count($headers) < 1 )
                {
                    $errorMessage = 'file is empty or header malformed';
                    return false;
                }

                $uniqueCheck = Array();

                foreach( $headers as &$h )
                {
                    if( strlen($h) < 1 )
                    {
                        $errorMessage = 'one of the header column name is empty';
                        return false;
                    }
                    if( isset($uniqueCheck[$h]) )
                    {
                        $errorMessage = "two or more headers columns have same name '$h'";
                        return false;
                    }

                    $uniqueCheck[$h] = true;
                }

            }
            else
            {
                if( !is_array($customHeaders) )
                {
                    $errorMessage = "two or more headers columns have same name '$h'";
                    return false;
                }

                $headers = Array();

                foreach( $customHeaders as &$h )
                {
                    if( strlen($h) < 1 )
                    {
                        $errorMessage = 'one of the header column name is empty';
                        return false;
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
                $errorMessage = 'one line is empty';
                return false;
            }

            $explodedLine = explode(',', $line);
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
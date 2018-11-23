<?php

/*
 * Copyright (c) 2015 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud <cpainchaud _AT_ paloaltonetworks.com>
 *
 * This piece of software is solely for the use of PAN Professional Service
 * Engineers.
 *
 * DO NOT COPY OR REDISTRIBUTE without prior written consent from
 * PAN Professional Services representative.
 */


print "\n************* START OF SCRIPT ".basename(__FILE__)." ************\n\n";

require_once "lib/panconfigurator.php";

PH::processCliArgs();


function display_usage_and_exit()
{
    global $argv;
    print PH::boldText("USAGE: ")."php ".basename(__FILE__)." file1=original.xml file2=compare.xml".
        "\n";

    exit(1);
}

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ").$msg."\n\n");
    display_usage_and_exit();
}

if( ! isset(PH::$args['file1']) )
    display_error_usage_exit('"file1" is missing from arguments');
$file1 = PH::$args['file1'];
if( !is_string($file1) || strlen($file1) < 1 )
    display_error_usage_exit('"file1" argument is not a valid string');

if( ! isset(PH::$args['file2']) )
    display_error_usage_exit('"file2" is missing from arguments');
$file2 = PH::$args['file2'];
if( !is_string($file2) || strlen($file2) < 1 )
    display_error_usage_exit('"file1" argument is not a valid string');

print "Opening ORIGINAL '{$file1}' XML file... ";
$doc1 = new DOMDocument();
if( $doc1->load($file1) === false )
    derr( 'Error while parsing xml:'.libxml_get_last_error()->message );
print "OK!\n";

    print "Opening COMPARE '{$file2}' XML file... ";
$doc2 = new DOMDocument();
if( $doc2->load($file2) === false )
    derr( 'Error while parsing xml:'.libxml_get_last_error()->message );
print "OK!\n";

print "*** NOW DISPLAY DIFF ***\n\n";


/**
 * @param DOMElement $el1
 * @param DOMElement $el2
 */
function compareElements($el1, $el2)
{
    $xpath = DH::elementToPanXPath($el1);

    //print "*** COMPARING {$xpath}\n";

    /** @var DOMElement[][] $el1Elements */
    $el1Elements = Array();
    /** @var DOMElement[][] $el2Elements */
    $el2Elements = Array();

    /** @var DOMElement[][] $plus */
    $plus = Array();
    /** @var DOMElement[][ $minus */
    $minus = Array();

    foreach( $el1->childNodes as $node )
    {
        /** @var DOMElement $node */
        if( $node->nodeType != XML_ELEMENT_NODE )
            continue;

        $el1Elements[$node->tagName][] = $node;
    }

    foreach( $el2->childNodes as $node )
    {
        /** @var DOMElement $node */
        if( $node->nodeType != XML_ELEMENT_NODE )
            continue;

        $el2Elements[$node->tagName][] = $node;
    }

    if( count($el1Elements) == 0 && count($el2Elements) == 0 )
    {
        $el1Trim = trim($el1->textContent);
        $el2Trim = trim($el2->textContent);

        if( $el1Trim != $el2Trim )
        {
            $text = '';


            $tmp = DH::dom_to_xml($el1);
            $text .= '+'.str_replace("\n", "\n", $tmp);

            $tmp = DH::dom_to_xml($el2);
            $text .= '-'.str_replace("\n", "\n", $tmp);


            if( $text != '' )
            {
                print "\nXPATH: $xpath\n";
                print "$text\n";
            }

            /* OLD OUTPUT
            #$xpath = DH::elementToPanXPath($el1);
            #print "\nXPATH: {$xpath}\n";
            #print "- {$el1Trim}\n";
            #print "+ {$el2Trim}\n";
            */
        }
        return;
    }

    //
    //  nodes missing entirely in one or the other
    //
    foreach($el1Elements as $tagName => &$nodeArray1 )
    {
        if( !isset($el2Elements[$tagName]) )
        {
            foreach( $nodeArray1 as $node )
            {
                $minus[] = $node;
            }

            unset($el1Elements[$tagName]);
        }
    }
    foreach($el2Elements as $tagName => &$nodeArray2 )
    {
        if( !isset($el1Elements[$tagName]) )
        {
            foreach( $nodeArray2 as $node )
            {
                $plus[] = $node;
            }
            unset($el2Elements[$tagName]);
        }
    }

    // conflicting objects
    foreach($el1Elements as $tagName => &$nodeArray1 )
    {
        //print "checking $xpath/$tagName\n";
        $nodeArray2 = &$el2Elements[$tagName];

        $el1BasicNode = null;
        foreach($nodeArray1 as $nodeIndex => $node)
        {
            if( !$node->hasAttribute('name') )
            {
                if( $el1BasicNode === null )
                {
                    $el1BasicNode = $node;
                    //print "found in EL1\n";
                }
                else
                {
                    if( is_array($el1BasicNode) )
                    {
                        $el1BasicNode[] = $node;
                    }
                    else
                    {
                        $el1BasicNode = Array($el1BasicNode);
                    }
                }

                unset($nodeArray1[$nodeIndex]);
            }
        }
        if( $el1BasicNode !== null && count($nodeArray1) > 0 )
            derr('unsupported situation where <node> and <node name=""> were both seen', $el1);

        $el2BasicNode = null;
        foreach($nodeArray2 as $nodeIndex => $node)
        {
            if( !$node->hasAttribute('name') )
            {
                if( $el2BasicNode === null )
                {
                    $el2BasicNode = $node;
                    //print "found in EL2\n";
                }
                else
                {
                    if( is_array($el2BasicNode) )
                    {
                        $el2BasicNode[] = $node;
                    }
                    else
                    {
                        $el2BasicNode = Array($el2BasicNode);
                    }
                }

                unset($nodeArray2[$nodeIndex]);
            }
        }
        if( $el2BasicNode !== null && count($nodeArray2) > 0 )
            derr('unsupported situation where <node> and <node name=""> where both seen in same document', $el2);

        if( $el1BasicNode === null && $el2BasicNode !== null )
            derr('found an issue where file1 has <node> but file2 has <node name="">');
        if( $el1BasicNode !== null && $el2BasicNode === null )
            derr('found an issue where file2 has <node> but file1 has <node name="">');


        if( $el1BasicNode !== null && $el2BasicNode !== null )
        {
            if( is_object($el1BasicNode)  && is_object($el2BasicNode) )
            {
                compareElements($el1BasicNode, $el2BasicNode);
            }
            else
            {
                if( is_object($el1BasicNode) )
                    $el1BasicNode = Array($el1BasicNode);
                if( is_object($el2BasicNode) )
                    $el2BasicNode = Array($el2BasicNode);

                $el1ContentSorted = Array();
                $el2ContentSorted = Array();

                foreach( $el1BasicNode as $node )
                {
                    $nodeContent = $node->textContent;
                    if( isset($el1ContentSorted[$nodeContent]) )
                        derr('cannot have <node>xxxx</node> nodes witch same content', $el1);
                }
                foreach( $el2BasicNode as $node )
                {
                    $nodeContent = $node->textContent;
                    if( isset($el2ContentSorted[$nodeContent]) )
                        derr('cannot have <node>xxxx</node> nodes witch same content', $el2);
                }

                foreach( $el1ContentSorted as $content => $node )
                {
                    if( isset($el2ContentSorted[$content]) )
                        continue;
                    $minus[] = $node;
                }
                foreach( $el2ContentSorted as $content => $node )
                {
                    if( isset($el1ContentSorted[$content]) )
                        continue;
                    $plus[] = $node;
                }

            }
        }
        elseif($el1BasicNode !== null && $el2BasicNode === null )
        {
            if( is_object($el1BasicNode) )
                $minus[] = $el1BasicNode;
            else
                foreach($el1BasicNode as $node )
                    $minus[] = $node;
        }
        elseif($el1BasicNode === null && $el2BasicNode !== null )
        {
            if( is_object($el2BasicNode) )
                $minus[] = $el2BasicNode;
            else
                foreach($el2BasicNode as $node )
                    $minus[] = $node;

        }
        else
        {
            $el1NameSorted = Array();
            $el2NameSorted = Array();

            foreach($nodeArray1 as $nodeIndex => $node)
            {
                $nodeName = $node->getAttribute('name');
                if( isset($el1NameSorted[$nodeName]) )
                    derr('<node name="'.$nodeName.'"> was found twice in file1', $el1);
                $el1NameSorted[$nodeName] = $node;
            }
            foreach($nodeArray2 as $nodeIndex => $node)
            {
                $nodeName = $node->getAttribute('name');
                if( isset($el2NameSorted[$nodeName]) )
                    derr('<node name="'.$nodeName.'"> was found twice in file2', $el2);
                $el2NameSorted[$nodeName] = $node;
            }

            foreach( $el1NameSorted as $nodeName => $node )
            {
                if( !isset($el2NameSorted[$nodeName]) )
                {
                    $minus[] = $node;
                    unset($el1NameSorted[$nodeName]);
                }
            }
            foreach( $el2NameSorted as $nodeName => $node )
            {
                if( !isset($el1NameSorted[$nodeName]) )
                {
                    $plus[] = $node;
                    unset($el2NameSorted[$nodeName]);
                }
            }

            foreach( $el1NameSorted as $nodeName => $node1 )
            {
                $node2 = $el2NameSorted[$nodeName];

                compareElements($node1, $node2);
            }

        }

        unset($el1Elements[$tagName]);
        unset($el2Elements[$tagName]);
    }






    $text = '';

    foreach($plus as $node)
    {
        $tmp = DH::dom_to_xml($node);
        $text .= '+'.str_replace("\n", "\n+", $tmp);
    }

    foreach($minus as $node)
    {
        $tmp = DH::dom_to_xml($node);
        $text .= '-'.str_replace("\n", "\n-", $tmp);
    }

    if( $text != '' )
    {
        print "\nXPATH: $xpath\n";
        print "$text\n";
    }

}

$doc1Root = DH::firstChildElement($doc1);
$doc2Root = DH::firstChildElement($doc2);

compareElements($doc1Root, $doc2Root);


print "\n\n************* END OF SCRIPT ".basename(__FILE__)." ************\n\n";









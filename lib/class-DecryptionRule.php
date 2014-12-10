<?php
/**
 * Created by PhpStorm.
 * User: cpainchaud
 * Date: 08/11/2014
 * Time: 17:30
 */

class DecryptionRule extends Rule
{

    public function DecryptionRule($owner, $fromtemplatexml=false)
    {
        $this->owner = $owner;

        $this->findParentAddressStore();
        $this->findParentServiceStore();

        $this->init_tags_with_store();
        $this->init_from_with_store();
        $this->init_to_with_store();
        $this->init_source_with_store();
        $this->init_destination_with_store();

        if( $fromtemplatexml )
        {
            if( is_null(self::$templatexmlroot) )
            {
                $xmlobj = new XmlArray();
                self::$templatexmlroot = $xmlobj->load_string(self::$templatexml);
                //print_r(self::$templatexmlroot);
                //derr();
            }
            $tmparr = cloneArray(self::$templatexmlroot);
            $this->load_from_xml($tmparr);
        }

    }

    public function load_from_xml(&$xml)
    {
        $this->xmlroot = &$xml;

        $this->name = $xml['attributes']['name'];

        if( is_null($this->name ) )
            derr("Rule name not found\n");

        $this->extract_disabled_from_xml();
        $this->extract_description_from_xml();

        $this->load_from();
        $this->load_to();
        $this->load_source();
        $this->load_destination();
        $this->load_tags();

    }

    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("name not found\n");

        $this->extract_disabled_from_domxml();
        $this->extract_description_from_domxml();


        $this->load_from();
        $this->load_to();
        $this->load_source();
        $this->load_destination();
        $this->load_tags();

    }

    public function display()
    {
        $dis = '';
        if( $this->disabled )
            $dis = '<disabled>';

        print "*Rule named '".$this->name."  $dis\n";
        print "  From: " .$this->from->toString_inline()."  |  To:  ".$this->to->toString_inline()."\n";
        print "  Source: ".$this->source->toString_inline()."\n";
        print "  Destination: ".$this->destination->toString_inline()."\n";
        print "    Tags:  ".$this->tags->toString_inline()."\n";
        print "\n";
    }

} 
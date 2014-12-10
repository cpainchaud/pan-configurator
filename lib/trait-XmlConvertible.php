<?php

trait XmlConvertible
{

	function &getXml_inline()
	{
		if( PH::$UseDomXML === TRUE )
		{
			return dom_to_xml($this->xmlroot, -1, false);
		}

		return array_to_xml($this->xmlroot, -1, false);
	}

	function &getXml( $indenting = true)
	{
		if( PH::$UseDomXML === TRUE )
		{
			if( $indenting )
				return dom_to_xml($this->xmlroot, 0, true);
			return dom_to_xml($this->xmlroot, -1, true);
		}

		if( $indenting )
				return array_to_xml($this->xmlroot, 0, true);
		return array_to_xml($this->xmlroot, -1, true);
	}

}


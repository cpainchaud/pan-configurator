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

class ManagedDevice
{
    use ReferencableObject;
    use PathableName;
    use XmlConvertible;

    /** @var  ManagedDeviceStore */
    public $owner;

    public $devicegroup;
    public $template;
    public $template_stack;


    function __construct( $name, $owner )
    {
        $this->owner = $owner;
        $this->name = $name;
    }



    public function addDeviceGroup( $devicegroup )
    {
        $this->devicegroup = $devicegroup;
    }

    public function addTemplate( $template )
    {
        $this->template = $template;
    }

    public function addTemplateStack( $template_stack )
    {
        $this->template_stack = $template_stack;
    }

    public function getDeviceGroup( )
    {
        return $this->devicegroup;
    }

    public function getTemplate(  )
    {
        return $this->template;
    }

    public function getTemplateStack( )
    {
        return $this->template_stack;
    }
}
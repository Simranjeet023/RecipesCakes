#pragma checksum "C:\Users\Owner\source\repos\SimuNikiCakes\SimuNikiCakes\Pages\_Layout.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "35f786e152ef3cf62157e3bfcfb7aec1a5f126e2"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(SimuNikiCakes.Pages.Pages__Layout), @"mvc.1.0.view", @"/Pages/_Layout.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Pages/_Layout.cshtml", typeof(SimuNikiCakes.Pages.Pages__Layout))]
namespace SimuNikiCakes.Pages
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#line 1 "C:\Users\Owner\source\repos\SimuNikiCakes\SimuNikiCakes\Pages\_ViewImports.cshtml"
using SimuNikiCakes.Models;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"35f786e152ef3cf62157e3bfcfb7aec1a5f126e2", @"/Pages/_Layout.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"238480c816ad8bd94e83891b91686351a1814e82", @"/Pages/_ViewImports.cshtml")]
    public class Pages__Layout : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("rel", new global::Microsoft.AspNetCore.Html.HtmlString("stylesheet"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("href", new global::Microsoft.AspNetCore.Html.HtmlString("~/site.css"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_2 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("method", "post", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_3 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-page", "/Account/Login", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_4 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-page-handler", "Logout", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        #line hidden
        #pragma warning disable 0169
        private string __tagHelperStringValueBuffer;
        #pragma warning restore 0169
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperExecutionContext __tagHelperExecutionContext;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner __tagHelperRunner = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner();
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __backed__tagHelperScopeManager = null;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __tagHelperScopeManager
        {
            get
            {
                if (__backed__tagHelperScopeManager == null)
                {
                    __backed__tagHelperScopeManager = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager(StartTagHelperWritingScope, EndTagHelperWritingScope);
                }
                return __backed__tagHelperScopeManager;
            }
        }
        private global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.HeadTagHelper __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_HeadTagHelper;
        private global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper;
        private global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.BodyTagHelper __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_BodyTagHelper;
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper;
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(0, 25, true);
            WriteLiteral("<!DOCTYPE html>\r\n<html>\r\n");
            EndContext();
            BeginContext(25, 106, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("head", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "9714e926a486474b9066efb3f691d13c", async() => {
                BeginContext(31, 48, true);
                WriteLiteral("\r\n    <title>Simu Niki Cake Design</title>\r\n    ");
                EndContext();
                BeginContext(79, 43, false);
                __tagHelperExecutionContext = __tagHelperScopeManager.Begin("link", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.SelfClosing, "4f693d959b88469aa1baf85b4ddaa060", async() => {
                }
                );
                __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
                __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
                __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_0);
                __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_1);
                await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
                if (!__tagHelperExecutionContext.Output.IsContentModified)
                {
                    await __tagHelperExecutionContext.SetOutputContentAsync();
                }
                Write(__tagHelperExecutionContext.Output);
                __tagHelperExecutionContext = __tagHelperScopeManager.End();
                EndContext();
                BeginContext(122, 2, true);
                WriteLiteral("\r\n");
                EndContext();
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_HeadTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.HeadTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_HeadTagHelper);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(131, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(133, 1580, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("body", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "7874028be3b6423588a076a6a5680b61", async() => {
                BeginContext(139, 668, true);
                WriteLiteral(@"
    <header class=""container site-header"">
        <div class=""row"">
            <h1 class=""main-logo""><a href=""/"">Welcome to Simu Niki Cake Design</a></h1>
        </div>
        <div class=""row"">
            <nav class=""navbar"">
                <ul class=""nav nav-pills"">
                    <li><a href=""/About"">About</a></li>
                    <li><a href=""/Blog"">Blog</a></li>
                    <li><a class=""active"" href=""/"">Recipes</a></li>
                    <li><a href=""/Portfolio"">Portfolio</a></li>
                    <li><a href=""/Contact"">Contact</a></li>
                </ul>
                <ul class=""nav nav-pills"">
					<li>
");
                EndContext();
#line 23 "C:\Users\Owner\source\repos\SimuNikiCakes\SimuNikiCakes\Pages\_Layout.cshtml"
                         if (!User.Identity.IsAuthenticated)
						{

#line default
#line hidden
                BeginContext(860, 43, true);
                WriteLiteral("\t\t\t\t\t\t\t<a href=\"/Account/Login\">Login</a>\r\n");
                EndContext();
#line 26 "C:\Users\Owner\source\repos\SimuNikiCakes\SimuNikiCakes\Pages\_Layout.cshtml"
						}
						else
						{

#line default
#line hidden
                BeginContext(933, 7, true);
                WriteLiteral("\t\t\t\t\t\t\t");
                EndContext();
                BeginContext(940, 251, false);
                __tagHelperExecutionContext = __tagHelperScopeManager.Begin("form", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "4deba65a1a1247ca92b665de05f09de2", async() => {
                    BeginContext(1012, 52, true);
                    WriteLiteral("\r\n\t\t\t\t\t\t\t\t<div class=\"input-group\">\r\n\t\t\t\t\t\t\t\t\t<span>");
                    EndContext();
                    BeginContext(1065, 18, false);
#line 31 "C:\Users\Owner\source\repos\SimuNikiCakes\SimuNikiCakes\Pages\_Layout.cshtml"
                                     Write(User.Identity.Name);

#line default
#line hidden
                    EndContext();
                    BeginContext(1083, 101, true);
                    WriteLiteral("</span>\r\n\t\t\t\t\t\t\t\t\t<button type=\"submit\" class=\"btn btn-link\">Logout</button>\r\n\t\t\t\t\t\t\t\t</div>\r\n\t\t\t\t\t\t\t");
                    EndContext();
                }
                );
                __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper>();
                __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper);
                __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper>();
                __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper);
                __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Method = (string)__tagHelperAttribute_2.Value;
                __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_2);
                __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Page = (string)__tagHelperAttribute_3.Value;
                __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_3);
                __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.PageHandler = (string)__tagHelperAttribute_4.Value;
                __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_4);
                await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
                if (!__tagHelperExecutionContext.Output.IsContentModified)
                {
                    await __tagHelperExecutionContext.SetOutputContentAsync();
                }
                Write(__tagHelperExecutionContext.Output);
                __tagHelperExecutionContext = __tagHelperScopeManager.End();
                EndContext();
                BeginContext(1191, 2, true);
                WriteLiteral("\r\n");
                EndContext();
#line 35 "C:\Users\Owner\source\repos\SimuNikiCakes\SimuNikiCakes\Pages\_Layout.cshtml"
						}

#line default
#line hidden
                BeginContext(1202, 94, true);
                WriteLiteral("\r\n\t\t\t\t\t</li>\r\n                </ul>\r\n            </nav>\r\n        </div>\r\n\t\t<div class=\"row\">\r\n");
                EndContext();
#line 42 "C:\Users\Owner\source\repos\SimuNikiCakes\SimuNikiCakes\Pages\_Layout.cshtml"
             if (IsSectionDefined("Title"))
			{
				

#line default
#line hidden
                BeginContext(1343, 39, false);
#line 44 "C:\Users\Owner\source\repos\SimuNikiCakes\SimuNikiCakes\Pages\_Layout.cshtml"
           Write(RenderSection("Title", required: false));

#line default
#line hidden
                EndContext();
#line 44 "C:\Users\Owner\source\repos\SimuNikiCakes\SimuNikiCakes\Pages\_Layout.cshtml"
                                                        
			}
			else
			{

#line default
#line hidden
                BeginContext(1405, 22, true);
                WriteLiteral("\t\t\t\t<h2 class=\"title\">");
                EndContext();
                BeginContext(1428, 17, false);
#line 48 "C:\Users\Owner\source\repos\SimuNikiCakes\SimuNikiCakes\Pages\_Layout.cshtml"
                             Write(ViewData["Title"]);

#line default
#line hidden
                EndContext();
                BeginContext(1445, 7, true);
                WriteLiteral("</h2>\r\n");
                EndContext();
#line 49 "C:\Users\Owner\source\repos\SimuNikiCakes\SimuNikiCakes\Pages\_Layout.cshtml"
			}

#line default
#line hidden
                BeginContext(1458, 64, true);
                WriteLiteral("\r\n\t\t</div>\r\n    </header>\r\n    <div class=\"container\">\r\n        ");
                EndContext();
                BeginContext(1523, 12, false);
#line 54 "C:\Users\Owner\source\repos\SimuNikiCakes\SimuNikiCakes\Pages\_Layout.cshtml"
   Write(RenderBody());

#line default
#line hidden
                EndContext();
                BeginContext(1535, 117, true);
                WriteLiteral("\r\n\r\n    </div>\r\n    <footer>\r\n        <div class=\"text-center\">\r\n            <span class=\"text-muted\">Last Rendered: ");
                EndContext();
                BeginContext(1653, 12, false);
#line 59 "C:\Users\Owner\source\repos\SimuNikiCakes\SimuNikiCakes\Pages\_Layout.cshtml"
                                               Write(DateTime.Now);

#line default
#line hidden
                EndContext();
                BeginContext(1665, 41, true);
                WriteLiteral(" </span>\r\n        </div>\r\n    </footer>\r\n");
                EndContext();
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_BodyTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.BodyTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_BodyTagHelper);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(1713, 9, true);
            WriteLiteral("\r\n</html>");
            EndContext();
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public IRecipesService RecipesService { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<dynamic> Html { get; private set; }
    }
}
#pragma warning restore 1591
